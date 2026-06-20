import json
import uuid


def create_packet(payload: str) -> dict:
    return {
        "request_id": str(uuid.uuid4()),
        "payload": payload,
        "history": [],
        "trust_score": None,
        "trust_decision": None,
        "detected_patterns": [],
        "report": None,
        "groq_response": None,
        "sanitized_input": None,
        "processing_times": {},
    }


def serialize(packet: dict) -> bytes:
    return json.dumps(packet).encode()


def deserialize(data: bytes) -> dict:
    return json.loads(data.decode())
