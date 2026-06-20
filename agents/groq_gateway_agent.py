"""
agents/groq_gateway_agent.py  —  Groq Gateway with PQC wrapping.
Model: llama-3.3-70b-versatile  (replaces decommissioned llama3-8b-8192)
"""
import os, time, re

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

from security.pqc_channel import send_secure, PQCKeyPair

GROQ_MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = """You are SentinelX AI, a secure AI security analyst.
Given a website security evaluation, provide a concise 3-4 sentence assessment that:
1. Acknowledges the risk level found
2. Names the most critical threat detected
3. Gives one concrete remediation recommendation
Keep it professional and under 100 words."""


class GroqGatewayAgent:

    def __init__(self, keypair: "PQCKeyPair" = None):
        self.name    = "Groq"
        self.keypair = keypair or PQCKeyPair("groq")
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.client  = Groq(api_key=self.api_key) if (GROQ_AVAILABLE and self.api_key) else None

    def process(self, packet: dict, coordinator_keypair: "PQCKeyPair" = None) -> dict:
        t0 = time.time()

        # Hop: Coordinator → [PQC] → Groq Gateway
        packet = send_secure("coordinator", "groq", self.keypair, packet)

        scan          = packet.get("website_scan", {})
        ri            = scan.get("risk_indicators", [])
        ts            = packet.get("trust_score", 100)
        rl            = packet.get("risk_level", "LOW")
        atk           = packet.get("attack_simulation", [])
        blocked_count = sum(1 for a in atk if a["status"] == "BLOCKED")

        user_prompt = (
            f"Website: {packet.get('url','unknown')}\n"
            f"Trust Score: {ts}/100 | Risk Level: {rl}\n"
            f"Forms: {scan.get('forms',0)} | Scripts: {scan.get('scripts',0)} | Inputs: {scan.get('inputs',0)}\n"
            f"Risk Indicators: {', '.join(ri) if ri else 'None'}\n"
            f"Attack simulations: {len(atk)} total, {blocked_count} BLOCKED\n"
            f"Missing security headers: {', '.join(scan.get('headers_missing',[])) or 'None'}\n"
            f"\nProvide your security assessment."
        )

        if self.client:
            try:
                resp = self.client.chat.completions.create(
                    model=GROQ_MODEL,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": user_prompt},
                    ],
                    max_tokens=200,
                    temperature=0.5,
                )
                raw_response = resp.choices[0].message.content
                packet["groq_model"] = resp.model
            except Exception as e:
                raw_response = f"[Groq API Error] {e}"
                packet["groq_model"] = "error"
        else:
            ri_text = ri[0] if ri else "no critical indicators"
            raw_response = (
                f"Security assessment for {packet.get('url','the target')}: "
                f"Trust Score {ts}/100 indicates a {rl.lower()} risk profile. "
                f"Primary concern is {ri_text}. "
                f"{blocked_count} of {len(atk)} simulated attacks were blocked by SentinelX. "
                f"Recommend hardening CSP headers and reviewing form input validation. "
                f"(Demo mode — set GROQ_API_KEY for live analysis.)"
            )
            packet["groq_model"] = "demo"

        # Hop: Groq Gateway → [PQC] → Coordinator
        coord_kp = coordinator_keypair or PQCKeyPair("coordinator_recv")
        response_packet = send_secure("groq", "coordinator", coord_kp, {**packet, "raw_llm_response": raw_response})

        sanitized_response = _sanitize_llm_output(raw_response)
        response_packet["groq_response"]           = sanitized_response
        response_packet["groq_response_sanitized"] = (sanitized_response != raw_response)
        response_packet["history"].append("groq")
        response_packet["processing_times"]["groq"] = round((time.time() - t0) * 1000, 1)
        return response_packet


def _sanitize_llm_output(text: str) -> str:
    patterns = [
        r"ignore\s+(previous|all|system)\s+(instructions?|prompts?)",
        r"forget\s+(everything|all)",
        r"you\s+are\s+now\s+DAN",
        r"<script.*?>.*?</script>",
        r"system\s*:\s*",
    ]
    for p in patterns:
        text = re.sub(p, "[REMOVED]", text, flags=re.IGNORECASE | re.DOTALL)
    return text.strip()
