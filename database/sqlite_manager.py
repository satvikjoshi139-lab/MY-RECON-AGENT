import sqlite3, json, os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sentinelx.db")

class SQLiteManager:
    _instance = None
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_db()
        return cls._instance

    def _init_db(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                request_id  TEXT PRIMARY KEY,
                timestamp   TEXT NOT NULL,
                url         TEXT NOT NULL,
                trust_score INTEGER,
                risk_level  TEXT,
                decision    TEXT,
                threat_count INTEGER,
                blocked     INTEGER DEFAULT 0,
                groq_model  TEXT,
                result      TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def save(self, packet: dict):
        report = packet.get("report") or {}
        self.conn.execute(
            "INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                packet["request_id"],
                report.get("timestamp", datetime.utcnow().isoformat()),
                packet.get("url", ""),
                packet.get("trust_score"),
                packet.get("risk_level"),
                packet.get("trust_decision"),
                packet.get("threat_count", 0),
                int(packet.get("blocked", False)),
                packet.get("groq_model", ""),
                json.dumps({k:v for k,v in packet.items() if k != "pqc_log"}, default=str),
            )
        )
        self.conn.commit()

    def get_all(self, limit=100):
        cur = self.conn.execute(
            "SELECT * FROM reports ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]

    def get_stats(self):
        cur = self.conn.execute("""
            SELECT COUNT(*) AS total, AVG(trust_score) AS avg_score,
                   SUM(blocked) AS blocked_count,
                   SUM(CASE WHEN risk_level='HIGH'   THEN 1 ELSE 0 END) AS high_risk,
                   SUM(CASE WHEN risk_level='MEDIUM' THEN 1 ELSE 0 END) AS medium_risk,
                   SUM(CASE WHEN risk_level='LOW'    THEN 1 ELSE 0 END) AS low_risk,
                   SUM(threat_count) AS total_threats
            FROM reports
        """)
        row = cur.fetchone()
        if not row or row["total"] == 0:
            return dict(total=0, avg_score=100, blocked_count=0,
                        high_risk=0, medium_risk=0, low_risk=0, total_threats=0)
        return dict(row)

    def get_threat_breakdown(self):
        bd = dict(prompt_injection=0, jailbreak=0, exfiltration=0,
                  memory_poison=0, tool_hijack=0)
        for row in self.get_all(1000):
            try:
                p = json.loads(row["result"])
                for k in bd:
                    if (p.get("threat_summary") or {}).get(k):
                        bd[k] += 1
            except: pass
        return bd

    def get_recent(self, n=10): return self.get_all(limit=n)
    def clear(self):
        self.conn.execute("DELETE FROM reports"); self.conn.commit()
