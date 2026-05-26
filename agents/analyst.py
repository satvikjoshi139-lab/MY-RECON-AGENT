from agents.tools import (enumerate_subdomains, dns_resolve, check_port,
                          http_probe, vulnerability_scan)
from agents.state import AgentState, Task, Finding
import json, uuid

COMMON_PORTS = [80, 443, 8080, 8443, 22, 21, 25, 3306, 5432]

async def analyst_node(state: AgentState) -> AgentState:
    pending = [t for t in state["plan"] if t["status"] == "pending"]
    if not pending:
        state["phase"] = "reporting"
        return state

    task = pending[0]
    task["status"] = "running"
    tool = task["tool"]
    args = task["args"]

    try:
        if tool == "subdomain_enum":
            subdomains = await enumerate_subdomains(args)
            for sub in subdomains:
                state["findings"].append(Finding(
                    host=sub, port=None, service=None,
                    title="Subdomain discovered", severity="info",
                    description=f"Found subdomain: {sub}",
                    evidence=f"crt.sh: {sub}", remediation=""
                ))
            for sub in subdomains[:10]:
                state["plan"].append(Task(
                    task_id=str(uuid.uuid4())[:8],
                    tool="dns_resolve", args=sub,
                    purpose=f"Resolve {sub}", status="pending"
                ))

        elif tool == "dns_resolve":
            ips = await dns_resolve(args)
            for ip in ips:
                state["findings"].append(Finding(
                    host=args, port=None, service=None,
                    title="DNS resolution", severity="info",
                    description=f"{args} resolves to {ip}",
                    evidence=str(ips), remediation=""
                ))
                state["plan"].append(Task(
                    task_id=str(uuid.uuid4())[:8],
                    tool="port_scan", args=ip,
                    purpose=f"Port scan {ip}", status="pending"
                ))

        elif tool == "port_scan":
            ip = args
            for port in COMMON_PORTS:
                if await check_port(ip, port, timeout=1.5):
                    state["findings"].append(Finding(
                        host=ip, port=port, service=str(port),
                        title=f"Open port {port}", severity="info",
                        description=f"Port {port} is open on {ip}",
                        evidence=f"TCP connect succeeded on {ip}:{port}", remediation=""
                    ))
                    if port in (80, 443, 8080, 8443):
                        scheme = "https" if port in (443, 8443) else "http"
                        url = f"{scheme}://{ip}:{port}"
                        state["plan"].append(Task(
                            task_id=str(uuid.uuid4())[:8],
                            tool="http_probe", args=url,
                            purpose=f"HTTP probe {url}", status="pending"
                        ))

        elif tool == "http_probe":
            result = await http_probe(args)
            tech = result.get("tech", [])
            state["findings"].append(Finding(
                host=args, port=None, service="http",
                title=f"HTTP {result.get('status')} - {result.get('title','')}",
                severity="info",
                description=f"Technologies: {tech}",
                evidence=json.dumps(result), remediation=""
            ))
            state["plan"].append(Task(
                task_id=str(uuid.uuid4())[:8],
                tool="vuln_scan", args=args,
                purpose=f"Vulnerability scan {args}", status="pending"
            ))

        elif tool == "vuln_scan":
            vulns = await vulnerability_scan(args)
            for v in vulns:
                state["findings"].append(Finding(
                    host=args, port=None, service="http",
                    title=v["title"], severity=v["severity"],
                    description=v["desc"],
                    evidence="", remediation=v.get("remediation", "")
                ))
        task["status"] = "completed"
    except Exception as e:
        task["status"] = "failed"
        state["error"] = str(e)

    if all(t["status"] in ["completed", "failed"] for t in state["plan"]):
        state["phase"] = "reporting"
    return state