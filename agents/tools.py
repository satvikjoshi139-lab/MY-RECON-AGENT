import socket
import asyncio
import aiohttp
import json
from typing import List

async def enumerate_subdomains(domain: str) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as resp:
                data = await resp.json()
                subdomains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n.endswith(f".{domain}") or n == domain:
                            subdomains.add(n)
                return list(subdomains)
    except Exception:
        return []

async def dns_resolve(hostname: str) -> List[str]:
    try:
        loop = asyncio.get_event_loop()
        addrs = await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
        ips = list(set(a[4][0] for a in addrs))
        return ips
    except Exception:
        return []

COMMON_PORTS = [80, 443, 8080, 8443, 22, 21, 25, 3306, 5432]

async def check_port(ip: str, port: int, timeout=2) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def http_probe(url: str) -> dict:
    result = {"url": url, "status": None, "title": "", "headers": {}, "tech": []}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5, allow_redirects=True, ssl=False) as resp:
                result["status"] = resp.status
                result["headers"] = dict(resp.headers)
                body = await resp.text()
                if "<title>" in body:
                    start = body.find("<title>") + 7
                    end = body.find("</title>", start)
                    result["title"] = body[start:end].strip()
                if "X-Powered-By" in result["headers"]:
                    result["tech"].append(result["headers"]["X-Powered-By"])
                if "Server" in result["headers"]:
                    result["tech"].append(result["headers"]["Server"])
    except Exception:
        pass
    return result

async def vulnerability_scan(url: str) -> List[dict]:
    vulns = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5, ssl=False) as resp:
                headers = resp.headers
                if "X-Frame-Options" not in headers:
                    vulns.append({"title": "Missing X-Frame-Options", "severity": "medium",
                                  "desc": "Clickjacking possible", "remediation": "Add X-Frame-Options DENY header."})
                if "Content-Security-Policy" not in headers:
                    vulns.append({"title": "Missing Content-Security-Policy", "severity": "medium",
                                  "desc": "No CSP header present", "remediation": "Implement a strict CSP."})
                if "Strict-Transport-Security" not in headers and url.startswith("https"):
                    vulns.append({"title": "Missing HSTS", "severity": "medium",
                                  "desc": "No HSTS header on HTTPS", "remediation": "Add Strict-Transport-Security header."})
                git_url = url.rstrip("/") + "/.git/HEAD"
                try:
                    async with session.get(git_url, timeout=3) as git_resp:
                        if git_resp.status == 200:
                            vulns.append({"title": "Exposed .git directory", "severity": "high",
                                          "desc": "Git repository exposed", "remediation": "Restrict access to .git folder."})
                except:
                    pass
    except:
        pass
    return vulns