import os
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import quote_plus

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.collection import Collection
from datetime import datetime
import json

from phaseAgent import agent, memory

app = FastAPI(title="Scam Honeypot Agent API", version="1.0")


load_dotenv()


def _get_mongo_collection() -> Collection:
    mongo_uri = os.getenv("MONGODB_URI")
    if not mongo_uri:
        password = os.getenv("MONGODB_PASSWORD")
        if not password:
            raise HTTPException(
                status_code=500,
                detail="Server misconfigured: set MONGODB_URI or MONGODB_PASSWORD",
            )
        safe_password = quote_plus(password)
        mongo_uri = (
            "mongodb+srv://honeyAgent:{password}@cluster0.2e2ev0f.mongodb.net/?appName=Cluster0"
        ).format(password=safe_password)

    client = MongoClient(
        mongo_uri,
        serverSelectionTimeoutMS=5000,
        tls=True,
        tlsAllowInvalidCertificates=False,
        retryWrites=False,
        socketTimeoutMS=20000,
        connectTimeoutMS=20000,
    )
    db_name = os.getenv("MONGODB_DB", "honeypot")
    collection_name = os.getenv("MONGODB_COLLECTION", "sessions")
    return client[db_name][collection_name]


def require_api_key(x_api_key: Optional[str] = Header(default=None, alias="x-api-key")) -> str:
    expected = os.getenv("API_KEY") or os.getenv("SCAM_API_KEY")
    if not expected:
        raise HTTPException(
            status_code=500,
            detail="Server misconfigured: API_KEY (or SCAM_API_KEY) env var is not set",
        )
    if not x_api_key or x_api_key != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return x_api_key


class IncomingMessage(BaseModel):
    sender: Literal["scammer", "user"]
    text: str
    timestamp: str


class ConversationItem(BaseModel):
    sender: Literal["scammer", "user"]
    text: str
    timestamp: str


class Metadata(BaseModel):
    channel: str = "SMS"
    language: str = "English"
    locale: str = "IN"


class MessageEvent(BaseModel):
    sessionId: str = Field(..., min_length=1)
    message: IncomingMessage
    conversationHistory: List[ConversationItem] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=Metadata)


class MinimalMessageResponse(BaseModel):
    status: Literal["success"]
    reply: str


class AgentResponse(BaseModel):
    status: Literal["success"]
    sessionId: str
    reply: str
    scamDetected: bool
    extractedIntelligence: Dict[str, Any]
    evidenceStrength: Literal["LOW", "MEDIUM", "HIGH"]
    confidenceScore: int


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


def _format_history(history: List[ConversationItem]) -> List[str]:
    formatted: List[str] = []
    for item in history:
        if item.sender == "scammer":
            formatted.append(f"Scammer: {item.text}")
        else:
            formatted.append(f"user: {item.text}")
    return formatted


def _compute_evidence_strength(intel: Dict[str, Any]) -> tuple[int, str]:
    confidence_score = (
        len(intel.get("upiIds", []) or [])
        + len(intel.get("phishingLinks", []) or [])
        + len(intel.get("phoneNumbers", []) or [])
        + len(intel.get("keywords", []) or [])
        + len(intel.get("employeeIds", []) or [])
        + len(intel.get("references", []) or [])
        + len(intel.get("bankAccounts", []) or [])
    )

    if confidence_score >= 5:
        level = "HIGH"
    elif confidence_score >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    return confidence_score, level


@app.post("/message", response_model=MinimalMessageResponse, dependencies=[Depends(require_api_key)])
async def message_event(req: MessageEvent) -> MinimalMessageResponse:
    thread_id = req.sessionId
    thread_config = {
        "configurable": {"thread_id": thread_id},
        "thread_id": thread_id,
    }

    collection = _get_mongo_collection()

    checkpoint = memory.get(thread_config)
    is_new_thread = checkpoint is None

    payload: Dict[str, Any] = {
        "latest_message": req.message.text,
        "session_id": req.sessionId,
    }

    # If this is the first time we see this sessionId in this running server,
    # seed the agent with any provided conversation history.
    if req.conversationHistory:
        payload["conversation"] = _format_history(req.conversationHistory)
        payload["message_count"] = len(req.conversationHistory)
        

    try:
        result = agent.invoke(payload, config=thread_config)
    except Exception as e:
        msg = str(e)
        if len(msg) > 400:
            msg = msg[:400] + "..."
        raise HTTPException(
            status_code=500,
            detail=f"Agent invocation failed: {e.__class__.__name__}: {msg}",
        )

    if not isinstance(result, dict):
        raise HTTPException(status_code=500, detail="Agent returned unexpected result type")

    reply = str(result.get("reply", ""))
    scam_detected = bool(result.get("scam_detected", False))
    intel = result.get("intelligence", {})
    if not isinstance(intel, dict):
        intel = {}

    confidence_score, evidence_strength = _compute_evidence_strength(intel)

    now = datetime.utcnow().isoformat() + "Z"
    turn_doc: Dict[str, Any] = {
        "incoming": {
            "sender": req.message.sender,
            "text": req.message.text,
            "timestamp": req.message.timestamp,
        },
        "reply": reply,
        "storedAt": now,
    }

    update: Dict[str, Any] = {
        "$set": {
            "sessionId": req.sessionId,
            "langgraphThreadId": thread_id,
            "updatedAt": now,
            "lastReply": reply,
            "scamDetected": scam_detected,
            "extractedIntelligence": intel,
            "evidenceStrength": evidence_strength,
            "confidenceScore": confidence_score,
            "metadata": req.metadata or {},
        },
        "$setOnInsert": {
            "createdAt": now,
        },
        "$push": {
            "turns": turn_doc,
        },
    }

    if is_new_thread and req.conversationHistory:
        update["$setOnInsert"]["seedConversationHistory"] = [
            {"sender": h.sender, "text": h.text, "timestamp": h.timestamp}
            for h in req.conversationHistory
        ]

    try:
        collection.update_one({"sessionId": req.sessionId}, update, upsert=True)
    except Exception as e:
        msg = str(e)
        if len(msg) > 400:
            msg = msg[:400] + "..."
        raise HTTPException(
            status_code=500,
            detail=f"Failed to persist session to MongoDB: {e.__class__.__name__}: {msg}",
        )

    return MinimalMessageResponse(status="success", reply=reply)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="0.0.0.0", port=8000, log_level="info")
