"""
agents/scanner_agent.py

Production Scanner Agent.
Detects prompt injection, jailbreak, and other threats.
No sockets - called directly by Coordinator.
"""
import time
from security.threat_detector import analyze_threats
from defenses.memory_sanitizer import sanitize_memory


class ScannerAgent:

    def __init__(self):
        self.name = "Scanner"

    def process(self, packet: dict) -> dict:
        t0 = time.time()

        payload = packet["payload"]

        # Run threat analysis
        analysis = analyze_threats(payload)

        # Run memory sanitizer
        sanitized = sanitize_memory(payload)

        packet["trust_score"] = analysis["score"]
        packet["trust_decision"] = analysis["decision"]
        packet["risk_level"] = analysis["risk_level"]
        packet["detected_patterns"] = analysis["detected_patterns"]
        packet["threat_count"] = analysis["threat_count"]
        packet["threat_summary"] = analysis["threat_summary"]
        packet["categories_hit"] = analysis["categories_hit"]
        packet["sanitized_input"] = sanitized["cleaned_memory"]
        packet["tokens_removed"] = sanitized["tokens_removed"]

        packet["history"].append("scanner")
        packet["processing_times"]["scanner"] = round((time.time() - t0) * 1000, 1)

        return packet
