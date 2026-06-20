"""
services/coordinator.py

PQC-secured Coordinator Pipeline.

Every agent-to-agent boundary uses send_secure():
  Coordinator → [PQC] → WebScanner
  WebScanner  → [PQC] → TrustAgent
  TrustAgent  → [PQC] → AttackSimulator
  AttackSim   → [PQC] → ReportAgent
  ReportAgent → [PQC] → GroqGateway
  GroqGateway → [PQC] → Coordinator   (LLM response return)
"""
import time
import uuid
from dotenv import load_dotenv
load_dotenv()

from security.pqc_channel import (
    PQCKeyPair,
    send_secure,
    clear_channel_log,
    get_channel_log,
)
from agents.website_scanner_agent  import WebsiteScannerAgent
from agents.attack_simulator_agent import AttackSimulatorAgent
from agents.trust_agent            import TrustAgent
from agents.report_agent           import ReportAgent
from agents.groq_gateway_agent     import GroqGatewayAgent
from database.sqlite_manager       import SQLiteManager


class Coordinator:

    def __init__(self):
        # Each agent gets its own PQC keypair
        self.keys = {
            "coordinator": PQCKeyPair("coordinator"),
            "web_scanner":      PQCKeyPair("web_scanner"),
            "trust":            PQCKeyPair("trust"),
            "attack_simulator": PQCKeyPair("attack_simulator"),
            "report":           PQCKeyPair("report"),
            "groq":             PQCKeyPair("groq"),
        }

        self.web_scanner      = WebsiteScannerAgent()
        self.attack_simulator = AttackSimulatorAgent()
        self.trust            = TrustAgent()
        self.report           = ReportAgent()
        self.groq             = GroqGatewayAgent(keypair=self.keys["groq"])
        self.db               = SQLiteManager()

    def process(self, url: str) -> dict:
        clear_channel_log()
        t_total = time.time()

        # Initial packet
        packet = {
            "request_id":       str(uuid.uuid4()),
            "url":              url,
            "payload":          f"Security evaluation of {url}",
            "history":          [],
            "trust_score":      None,
            "trust_decision":   None,
            "risk_level":       None,
            "detected_patterns":[],
            "threat_count":     0,
            "report":           None,
            "groq_response":    None,
            "processing_times": {},
            "blocked":          False,
        }

        # ── Hop 1: Coordinator → [PQC] → WebScanner ──────────────────────────
        packet = send_secure(
            "coordinator", "web_scanner",
            self.keys["web_scanner"], packet
        )
        packet = self.web_scanner.process(packet)

        # ── Compute trust score from website scan ──────────────────────────────
        scan = packet.get("website_scan", {})
        ri   = scan.get("risk_indicators", [])
        score = 100
        score -= min(len(ri) * 12, 60)          # up to -60 for risk indicators
        if scan.get("iframes"):       score -= 10
        if scan.get("risky_patterns"):score -= 15
        if not scan.get("reachable"): score  = 40
        score = max(score, 0)

        if score >= 80:
            decision, risk_level = "ALLOW",    "LOW"
        elif score >= 50:
            decision, risk_level = "SANITIZE", "MEDIUM"
        else:
            decision, risk_level = "BLOCK",    "HIGH"

        packet["trust_score"]    = score
        packet["trust_decision"] = decision
        packet["risk_level"]     = risk_level
        packet["risk_indicators"]= ri
        packet["threat_count"]   = len(ri)

        # ── Hop 2: WebScanner → [PQC] → TrustAgent ───────────────────────────
        packet = send_secure(
            "web_scanner", "trust",
            self.keys["trust"], packet
        )
        t0 = time.time()
        packet["history"].append("trust")
        packet["processing_times"]["trust"] = round((time.time() - t0) * 1000, 1)

        # ── Hop 3: TrustAgent → [PQC] → AttackSimulator ──────────────────────
        packet = send_secure(
            "trust", "attack_simulator",
            self.keys["attack_simulator"], packet
        )
        packet = self.attack_simulator.process(packet)

        # ── Hop 4: AttackSimulator → [PQC] → ReportAgent ─────────────────────
        packet = send_secure(
            "attack_simulator", "report",
            self.keys["report"], packet
        )
        t0 = time.time()
        from datetime import datetime
        packet["report"] = {
            "timestamp":      datetime.utcnow().isoformat(),
            "request_id":     packet["request_id"],
            "url":            url,
            "status":         "HIGH RISK" if risk_level == "HIGH" else (
                               "WARNING"  if risk_level == "MEDIUM" else "SAFE"),
            "risk_level":     risk_level,
            "trust_score":    score,
            "trust_decision": decision,
            "threat_count":   len(ri),
            "risk_indicators":ri,
        }
        packet["history"].append("report")
        packet["processing_times"]["report"] = round((time.time() - t0) * 1000, 1)

        # ── Hop 5 & 6: ReportAgent ↔ [PQC] ↔ Groq (handled inside agent) ─────
        packet = self.groq.process(packet, coordinator_keypair=self.keys["coordinator"])

        packet["total_time_ms"] = round((time.time() - t_total) * 1000, 1)
        packet["pqc_log"]       = get_channel_log()

        # Persist
        try:
            self.db.save(packet)
        except Exception as e:
            print(f"[Coordinator] DB error: {e}")

        return packet

    def get_stats(self)         -> dict: return self.db.get_stats()
    def get_recent(self, n=10)  -> list: return self.db.get_recent(n)
    def get_threat_breakdown(self)->dict: return self.db.get_threat_breakdown()
