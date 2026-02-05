import re
import os
import json
import uuid
import threading
import urllib.request
from datetime import datetime
from typing import TypedDict, List, Dict
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langgraph.checkpoint.memory import MemorySaver


load_dotenv()

llm = ChatGroq(
    groq_api_key=os.getenv("GROQ_API_KEY"),
    model_name="llama-3.3-70b-versatile",
    temperature=0.2
)


# ---------------- STATE ---------------- #

class AgentState(TypedDict):
    session_id: str
    latest_message: str
    reply: str
    intelligence: Dict
    scam_detected: bool
    message_count: int
    conversation: List[str]
    final_intel_sent: bool


# ---------------- SCAM DETECTION ---------------- #

def detect_scam(state: AgentState) -> AgentState:
    """Improved scam detection - catches more patterns"""
    
    if state.get("scam_detected", False):
        return state
    
    text = state["latest_message"]
    lowered = text.lower()
    
    scam_score = 0
    
    # 🔴 FINANCIAL REQUESTS (highest priority)
    money_patterns = [
        r'\d+k\s*(?:rupees|ruppes|rs|inr)',  # "50k rupees"
        r'(?:send|need|transfer|pay)\s*(?:me\s*)?(?:rs|rupees|money|\d+)',  # "send money", "need 50k"
        r'\d+\s*(?:thousand|lakh|lakhs)',  # "50 thousand"
    ]
    for pattern in money_patterns:
        if re.search(pattern, lowered):
            scam_score += 5  # Very strong indicator
    
    # 🔴 EMERGENCY/URGENCY TACTICS
    urgency_keywords = [
        "emergency", "urgent", "accident", "hospital", "operation",
        "immediately", "right now", "asap", "hurry", "quick"
    ]
    if any(word in lowered for word in urgency_keywords):
        scam_score += 3
    
    # 🔴 BANKING/FINANCIAL KEYWORDS
    strong_indicators = [
        "otp", "cvv", "pin", "password", "verification code",
        "blocked", "suspend", "frozen", "deactivate", "shut down",
        "minimum balance", "kyc", "verify account"
    ]
    for keyword in strong_indicators:
        if keyword in lowered:
            scam_score += 4
    
    # Bank impersonation
    banks = ["hdfc", "icici", "sbi", "axis", "kotak", "bank"]
    if any(bank in lowered for bank in banks):
        scam_score += 2
    
    # URLs (non-official)
    if re.search(r'https?://', text):
        if not re.search(r'https?://(?:www\.)?(icici|hdfc|sbi|axis|kotak)\.(com|co\.in)', text):
            scam_score += 4
    
    # UPI handles
    if re.search(r'[a-zA-Z0-9._-]+@(?:paytm|phonepe|googlepay|ok\w+|ybl|axl)', text, re.IGNORECASE):
        scam_score += 4
    
    # 🔴 DETECTION THRESHOLD
    if scam_score >= 3:
        state["scam_detected"] = True
        print(f"[SCAM DETECTED] Score: {scam_score}")
    
    return state


# ---------------- INTELLIGENCE EXTRACTION ---------------- #

def extract_intelligence(state: AgentState) -> AgentState:
    """Extract intelligence from conversation - rebuilds from full history if state is fresh"""
    
    text = state["latest_message"]
    intel = state.get("intelligence", {})
    conversation = state.get("conversation", [])
    
    # Initialize intel structure
    intel.setdefault("upiIds", [])
    intel.setdefault("phoneNumbers", [])
    intel.setdefault("phishingLinks", [])
    intel.setdefault("suspiciousKeywords", [])
    intel.setdefault("bankAccounts", [])
    
    # Check if this is fresh state (no intel yet) but conversation exists
    # This handles Railway restart where LangGraph memory is lost
    is_fresh_state = (
        not intel.get("upiIds") and 
        not intel.get("phoneNumbers") and 
        not intel.get("phishingLinks") and 
        not intel.get("suspiciousKeywords") and
        not intel.get("bankAccounts")
    )

    print(conversation)
    
    if conversation:
        # Re-extract from all historical messages in conversation
        for msg in conversation:
            if msg.startswith("Scammer:"):
                hist_text = msg.replace("Scammer: ", "", 1)
                _extract_patterns_from_text(hist_text, intel)
    
    # Always extract from the latest message
    _extract_patterns_from_text(text, intel)
    
    state["intelligence"] = intel
    
    # Update conversation
    conversation.append(f"Scammer: {text}")
    conversation.append(f"Victim: {state.get('reply', '')}")
    state["conversation"] = conversation[-30:]
    
    return state


def _extract_patterns_from_text(text: str, intel: Dict) -> None:
    """Extract UPI, phone, links, keywords, accounts from a single text message."""
    
    # UPI IDs - broader pattern
    upi_pattern = r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9]+\b'
    upis = re.findall(upi_pattern, text, re.IGNORECASE)
    for upi in upis:
        if upi.lower() not in [u.lower() for u in intel["upiIds"]]:
            intel["upiIds"].append(upi)
    
    # Phone numbers - multiple patterns
    phones_10 = re.findall(r'\b\d{10}\b', text)
    phones_8_9 = re.findall(r'\b\d{8,9}\b', text)
    all_phones = phones_10 + phones_8_9
    for phone in all_phones:
        if len(phone) == 10:
            formatted = f"+91{phone}"
        else:
            formatted = phone
        if formatted not in intel["phoneNumbers"] and phone not in intel["phoneNumbers"]:
            intel["phoneNumbers"].append(formatted)
    
    # Links
    links = re.findall(r'https?://\S+', text)
    for link in links:
        if link not in intel["phishingLinks"]:
            intel["phishingLinks"].append(link)
    
    # Keywords
    keywords = [
        "otp", "one time password", "verification code", "security code", "auth code",
        "urgent", "immediately", "right now", "within minutes", "last warning",
        "final notice", "act now", "limited time", "expire today", "deadline",
        "account blocked", "account suspended", "account freeze", "account locked",
        "bank account blocked", "account will be closed", "suspended", "freeze",
        "restricted", "deactivated",
        "verify", "verify now", "re-verify", "kyc", "update kyc", "complete kyc",
        "kyc pending", "document verification",
        "transfer", "send money", "pay now", "refund processing fee",
        "security deposit", "service charge", "processing fee",
        "minimum balance", "penalty charge", "fine", "settlement",
        "upi", "upi id", "google pay", "gpay", "phonepe", "paytm",
        "scan qr", "payment link", "collect request",
        "click link", "login link", "secure link", "update link",
        "http", "https", "short link", "bit.ly", "tinyurl",
        "password", "atm pin", "cvv", "card number", "debit card", "credit card",
        "net banking", "customer id",
        "emergency", "accident", "hospital", "operation", "police case",
        "legal action", "court notice", "arrest", "fraud case", "cyber crime",
        "lottery", "won prize", "gift card", "reward points", "cashback offer",
        "bonus", "free gift", "lucky draw",
        "job offer", "work from home", "loan approved", "instant loan",
        "processing loan", "credit score issue",
        "parcel", "courier", "delivery charge", "customs fee", "shipment hold",
        "bank staff", "customer care", "support team", "technical support",
        "sbi bank", "hdfc bank", "rbi notice", "income tax", "aadhaar update"
    ]
    
    lowered = text.lower()
    for keyword in keywords:
        if keyword in lowered and keyword not in intel["suspiciousKeywords"]:
            intel["suspiciousKeywords"].append(keyword)
    
    # Bank account patterns (XXXX-XXXX-XXXX)
    acc_pattern = re.compile(r'\b\d{4}-\d{4}-\d{4}\b')
    for acc in acc_pattern.findall(text):
        if acc not in intel["bankAccounts"]:
            intel["bankAccounts"].append(acc)
    
    # Money amounts
    money_patterns = [
        r'(\d+)k\s*(?:rupees|ruppes|rs)',
        r'(\d+)\s*(?:thousand|lakh)',
    ]
    for pattern in money_patterns:
        amounts = re.findall(pattern, lowered)
        for amount in amounts:
            amount_str = f"{amount}k" if "k" in lowered else amount
            if amount_str not in intel["bankAccounts"]:
                intel["bankAccounts"].append(amount_str)


# ---------------- REPLY GENERATOR ---------------- #

def generate_reply(state: AgentState) -> AgentState:
    """Natural, innocent, non-pushy replies"""

    conversation = state.get("conversation", [])
    context = "\n".join(conversation[-6:])

    scam_detected = state.get("scam_detected", False)
    message_count = state.get("message_count", 0)

    latest_msg = state["latest_message"].lower()

    # -----------------------
    # Context detection
    # -----------------------
    no_context = (
        message_count == 0
        or len(conversation) == 0
        or len(latest_msg.split()) <= 3
    )

    # -----------------------
    # Instruction logic
    # -----------------------

    if not scam_detected:
        # Non-scam mode: basic understanding only
        instruction = "Ask casually what this is about or what they need."

        prompt = f"""
You are chatting with someone on SMS in an Indian context.

You are a normal Indian person.Chat only in English
Casual, friendly, slightly confused, not tech-savvy.
You do NOT suspect a scam yet.

Recent chat:
{context}

Their latest message:
{state['latest_message']}

Your task:
{instruction}

Rules:
- 1–2 short sentences only
- Casual Indian ENGLISH only
- No quotes
- No explanations
- Do not ask for sensitive details

Reply with ONLY the message you would send.
"""

    else:
        # Scam-detected mode (but user does NOT know it is a scam)

        # 🟡 Abrupt / no-context message — highest priority
        if no_context:
            instruction = (
                "Sound confused and cautious. "
                "Ask who this is and what this message is regarding."
            )

        # 🚫 OTP / password handling
        elif any(word in latest_msg for word in ["otp", "password", "pin", "cvv"]):
            instruction = (
                "Say you will check later. "
                "Ask a simple question about what to do next."
            )

        # 💰 Money / transfer mentioned
        elif any(word in latest_msg for word in ["send", "transfer", "payment", "money"]):
            instruction = (
                "Sound unsure and slow. "
                "Ask how to do it, like via UPI or bank account."
            )

        # 🔗 Link mentioned
        elif "link" in latest_msg or "http" in latest_msg:
            instruction = (
                "Acknowledge the link. "
                "Ask what happens after opening it. "
                "Ask if it needs OTP or any details. "
                "Casually ask if there is a help line or customer care number."
            )

        # 💤 Passive continuation
        else:
            stalls = [
                "Say you're checking and ask how long it will take.",
                "Say you didn't fully understand and ask what to do next.",
                "Show mild concern and ask what happens if you don't do it now.",
                "Ask where you need to do this from."
            ]
            instruction = stalls[message_count % len(stalls)]

        prompt = f"""
You are chatting with someone on SMS in an Indian context.

You feel something is off, but you do NOT know it is a scam.
You stay cooperative, slow, and slightly worried. Chat only in English

Recent chat:
{context}

Their latest message:
{state['latest_message']}

Your task:
{instruction}

Important rules:
- Do NOT forcefully ask for UPI, links, phone, or bank details
- React only to what they mention
- If something was shared once, do NOT ask for it again deliberately
- NEVER share OTP, bank details, UPI, or money

Style:
- 1–2 short sentences only
- Casual Indian ENGLISH ONLY
- No quotes
- No explanations
- Sound vulnerable and human

Reply with ONLY the message you would send.
"""

    try:
        reply = llm.invoke(prompt).content.strip()
        reply = reply.strip('"').strip("'")
        reply = re.sub(r'\s+', ' ', reply)
    except Exception as e:
        print(f"Error: {e}")
        reply = "Let me check once, what should I do next?"

    state["reply"] = reply
    return state


# ---------------- INTEL SUBMISSION ---------------- #

def check_and_submit(state: AgentState) -> AgentState:
    """Submit ONCE when trigger reached, keep chatting"""
    
    # Skip if already submitted

    
    intel = state.get("intelligence", {})
    message_count = state.get("message_count", 0)
    latest_msg = state["latest_message"].lower()
    scam_detected = state.get("scam_detected", False)
    
    # Count MEANINGFUL intel (not empty arrays)
    intel_count = (
        len(intel.get("upiIds", [])) +
        len(intel.get("phoneNumbers", [])) +
        len(intel.get("phishingLinks", [])) +
        len(intel.get("bankAccounts", []))
    )
    
    should_submit = False
    is_goodbye = False
    
    # Trigger 1: Scammer says bye
    if latest_msg in ["bye", "ok bye", "exit", "quit", "thanks", "thank you", "talk later", "goodbye"]:
        should_submit = True
        is_goodbye = True
    
    # Trigger 2: Got 2+ REAL intel pieces AND scam detected
    elif scam_detected and intel_count >= 2:
        should_submit = True
    
    # Trigger 3: 8+ messages (extended from 6)
    elif message_count >= 8:
        should_submit = True
    
    # Submit
    if should_submit:
        summary = generate_summary(state)
        send_to_backend(summary)
        state["final_intel_sent"] = True
        
        if is_goodbye:
            # Generate exit message
            exit_prompt = "Say you'll check this out and thank them. 1 sentence, casual."
            try:
                exit_reply = llm.invoke(exit_prompt).content.strip().strip('"').strip("'")
                state["reply"] = exit_reply
            except:
                state["reply"] = "Okay da, let me check. Thanks!"
        else:
            # Don't change reply - keep conversation natural
            print("📤 [Intel submitted - conversation continues]")
    
    return state


# ---------------- SUMMARY ---------------- #

def generate_summary(state: AgentState) -> Dict:
    """Generate intel summary"""
    
    intel = state.get("intelligence", {})
    conversation = state.get("conversation", [])
    
    scammer_msgs = [msg for msg in conversation if msg.startswith("Scammer:")]
    
    tactics_prompt = f"""Analyze these scammer messages in 1-2 sentences:

{chr(10).join(scammer_msgs[-8:])}

What tactics are they using? What do they want?"""
    
    try:
        agent_notes = llm.invoke(tactics_prompt).content.strip()
    except:
        agent_notes = "Scammer used social engineering tactics"
    
    return {
        "sessionId": state.get("session_id", "unknown"),
        "timestamp": datetime.now().isoformat(),
        "scamDetected": state.get("scam_detected", False),
        "totalMessagesExchanged": state.get("message_count", 0),
        "extractedIntelligence": {
            "bankAccounts": intel.get("bankAccounts", []),
            "upiIds": intel.get("upiIds", []),
            "phishingLinks": intel.get("phishingLinks", []),
            "phoneNumbers": intel.get("phoneNumbers", []),
            "suspiciousKeywords": intel.get("suspiciousKeywords", [])
        },
        "agentNotes": agent_notes,
    }


# ---------------- BACKEND ---------------- #

def send_to_backend(payload: Dict):
    """Send to backend API"""
    
    url = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    
    
    if not url:
        print("⚠️  No backend URL configured")
        return
    
    def _worker():
        try:
            body = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            
            
            req = urllib.request.Request(url=url, data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=5) as response:
                print(f"✅ Intel sent to backend (status: {response.status})")
        except Exception as e:
            print(f"❌ Backend error: {e}")
    
    threading.Thread(target=_worker, daemon=True).start()


# ---------------- INIT ---------------- #

def initialize_state(state: AgentState) -> AgentState:
    if "session_id" not in state:
        state["session_id"] = str(uuid.uuid4())[:8]
    
    state.setdefault("reply", "")
    state.setdefault("conversation", [])
    state.setdefault("intelligence", {
        "upiIds": [],
        "phoneNumbers": [],
        "phishingLinks": [],
        "suspiciousKeywords": [],
        "bankAccounts": []
    })
    state.setdefault("scam_detected", False)
    state.setdefault("message_count", 0)
    state.setdefault("final_intel_sent", False)
    
    state["message_count"] += 1
    
    return state


# ---------------- WORKFLOW ---------------- #

workflow = StateGraph(AgentState)

workflow.add_node("init", initialize_state)
workflow.add_node("detect", detect_scam)
workflow.add_node("reply", generate_reply)
workflow.add_node("extract", extract_intelligence)
workflow.add_node("submit", check_and_submit)

workflow.set_entry_point("init")
workflow.add_edge("init", "detect")
workflow.add_edge("detect", "reply")
workflow.add_edge("reply", "extract")
workflow.add_edge("extract", "submit")
workflow.add_edge("submit", END)

memory = MemorySaver()
agent = workflow.compile(checkpointer=memory)


# ---------------- CHAT ---------------- #

def chat():
    print("\n" + "="*70)
    print("🍯 SCAM HONEYPOT - Fixed Version")
    print("="*70)
    print("✅ Detects: Money requests, emergencies, banking scams")
    print("✅ Extracts: UPI, phones, links, keywords")
    print("✅ Submits: ONCE when 2+ intel OR 8+ messages")
    print("✅ Exits: Only when scammer says bye")
    print("="*70 + "\n")
    
    thread_id = f"session-{uuid.uuid4().hex[:8]}"
    
    while True:
        msg = input("Scammer: ")
        
        if not msg.strip():
            continue
        
        if msg.lower() in ["quit", "stop"]:
            print("\n⏹️  Manual exit\n")
            break
        
        result = agent.invoke(
            {"latest_message": msg},
            config={"configurable": {"thread_id": thread_id}}
        )
        
        print(f"Victim: {result['reply']}\n")
        
        intel = result.get('intelligence', {})
        print(f"[Scam: {result.get('scam_detected')} | Msg: {result.get('message_count')} | "
              f"UPI: {len(intel.get('upiIds', []))} | Phone: {len(intel.get('phoneNumbers', []))} | "
              f"Links: {len(intel.get('phishingLinks', []))} | Submitted: {result.get('final_intel_sent')}]\n")
        
        if msg.lower() in ["bye", "ok bye", "exit", "thanks", "thank you", "talk later"]:
            print("👋 Conversation ended\n")
            break
    
    # Final report
    thread_config = {"configurable": {"thread_id": thread_id}}
    checkpoint = memory.get(thread_config) or {}
    final_state = checkpoint.get("channel_values", {}) if isinstance(checkpoint, dict) else {}
    
    summary = generate_summary(final_state)
    
    print("="*70)
    print("📊 FINAL REPORT")
    print("="*70)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print("="*70)


if __name__ == "__main__":
    chat()