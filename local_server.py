#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse
import asyncio
from pathlib import Path

# Import your LangGraph app
from agents.graph import create_app
from agents.state import AgentState

async def run_scan(target: str, scan_type: str) -> dict:
    """Run the multi-agent scan and return results."""
    app = create_app()
    initial_state = AgentState(
        target=target,
        scan_type=scan_type,
        tasks=[],
        findings=[],
        final_report="",
        # Add other fields if your AgentState requires them
    )
    final_state = await app.ainvoke(initial_state)
    
    report = final_state.get("final_report", "")
    findings = final_state.get("findings", [])
    findings_count = len(findings)
    
    # Simple risk logic (customize as needed)
    if findings_count > 5:
        risk = "high"
    elif findings_count > 0:
        risk = "medium"
    else:
        risk = "low"
    
    return {
        "report": report,
        "findings": findings_count,
        "overall_risk": risk
    }

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            try:
                with open("index.html", "rb") as f:
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(f.read())
            except FileNotFoundError:
                self.send_error(404, "index.html not found")
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/api/scan":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
                target = data.get("target")
                scan_type = data.get("scan_type", "quick")

                if not target:
                    self._send_json(400, {"error": "Missing target"})
                    return

                # Run the async scan
                result = asyncio.run(run_scan(target, scan_type))
                self._send_json(200, result)

            except Exception as e:
                self._send_json(500, {"error": str(e)})
        else:
            self.send_error(404)

    def _send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

def run_server(port=8080):
    server_address = ("", port)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"✅ Server running at http://localhost:{port}")
    print("   Press Ctrl+C to stop")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()