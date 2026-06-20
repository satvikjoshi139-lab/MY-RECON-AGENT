"""
agents/trust_agent.py

Production Trust Agent.
Applies trust decision: ALLOW / SANITIZE / BLOCK.
"""
import time


class TrustAgent:

    def __init__(self):
        self.name = "Trust"

    def process(self, packet: dict) -> dict:
        t0 = time.time()

        score = packet.get("trust_score", 100)
        decision = packet.get("trust_decision", "ALLOW")

        # Apply decision
        if decision == "BLOCK":
            packet["blocked"] = True
            packet["block_reason"] = (
                f"Prompt blocked — Trust Score: {score}/100. "
                f"High-risk patterns detected: {', '.join(packet.get('categories_hit', []))}"
            )
        elif decision == "SANITIZE":
            packet["blocked"] = False
            # Use sanitized input going forward
            packet["payload"] = packet.get("sanitized_input", packet["payload"])
        else:
            packet["blocked"] = False

        packet["history"].append("trust")
        packet["processing_times"]["trust"] = round((time.time() - t0) * 1000, 1)

        return packet
