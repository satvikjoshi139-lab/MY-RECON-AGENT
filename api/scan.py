from http.server import BaseHTTPRequestHandler
import json
from agents.graph import create_app
from agents.state import AgentState
import asyncio
from dotenv import load_dotenv
load_dotenv()   # ensure Groq key is loaded

app = create_app()

def compute_overall_risk(findings: list) -> str:
    severities = [f.get("severity", "info") for f in findings]
    if "critical" in severities or "high" in severities:
        return "high"
    elif "medium" in severities:
        return "medium"
    else:
        return "low"

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        data = json.loads(body)
        target = data.get("target", "")
        scan_type = data.get("scan_type", "quick")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        initial_state = AgentState(
            target=target,
            scan_type=scan_type,
            plan=[],
            findings=[],
            phase="planning",
            error=None,
            final_report=None
        )
        final_state = loop.run_until_complete(app.ainvoke(initial_state))

        findings = final_state.get("findings", [])
        overall_risk = compute_overall_risk(findings) if scan_type != "ai_demo" else "info"

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response = {
            "report": final_state.get("final_report"),
            "findings_count": len(findings),
            "error": final_state.get("error"),
            "overall_risk": overall_risk
        }
        self.wfile.write(json.dumps(response).encode())