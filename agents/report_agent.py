"""
agents/report_agent.py

Production Report Agent.
Generates structured security report from packet data.
"""
import time
from datetime import datetime


class ReportAgent:

    def __init__(self):
        self.name = "Report"

    def process(self, packet: dict) -> dict:
        t0 = time.time()

        score = packet.get("trust_score", 100)
        decision = packet.get("trust_decision", "ALLOW")
        risk = packet.get("risk_level", "LOW")
        threats = packet.get("detected_patterns", [])
        blocked = packet.get("blocked", False)

        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": packet["request_id"],
            "status": "BLOCKED" if blocked else ("SAFE" if risk == "LOW" else "WARNING"),
            "risk_level": risk,
            "trust_score": score,
            "trust_decision": decision,
            "threat_count": len(threats),
            "threats_detected": [t["label"] for t in threats],
            "categories": packet.get("categories_hit", []),
            "tokens_removed": packet.get("tokens_removed", []),
            "payload_length": len(packet.get("payload", "")),
        }

        packet["report"] = report
        packet["history"].append("report")
        packet["processing_times"]["report"] = round((time.time() - t0) * 1000, 1)

        return packet
