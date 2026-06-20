"""
agents/website_scanner_agent.py

Scans a target URL for surface area, security headers,
JS libraries, risky patterns, and risk indicators.
"""
import time
import re

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    from bs4 import BeautifulSoup
    WEB_AVAILABLE = True
except ImportError as _e:
    WEB_AVAILABLE = False
    _MISSING = str(_e)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

JS_LIBS = [
    ("jQuery",    r"jquery"),
    ("React",     r"react"),
    ("Vue",       r"vue\.js|vue\.min"),
    ("Angular",   r"angular"),
    ("Bootstrap", r"bootstrap"),
    ("Lodash",    r"lodash"),
    ("Next.js",   r"next\.js|_next/"),
    ("Webpack",   r"webpack"),
]

RISKY_SCRIPT_PATTERNS = [
    r"eval\s*\(",
    r"document\.write\s*\(",
    r"innerHTML\s*=",
    r"dangerouslySetInnerHTML",
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _clean_url(url: str) -> str:
    """Ensure URL has a scheme and strip obvious redirect wrappers."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def scan_website(url: str) -> dict:
    t0 = time.time()
    url = _clean_url(url)

    result = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "forms": 0,
        "scripts": 0,
        "inputs": 0,
        "links": 0,
        "iframes": 0,
        "js_libs": [],
        "risky_patterns": [],
        "risk_indicators": [],
        "cookies": [],
        "headers_missing": [],
        "scan_time_ms": 0,
        "error": None,
    }

    if not WEB_AVAILABLE:
        result["error"] = (
            f"Missing packages — run: pip install requests beautifulsoup4\n"
            f"Detail: {_MISSING}"
        )
        result["scan_time_ms"] = 0
        return result

    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=12,
            verify=False,
            allow_redirects=True,
        )
        result["reachable"]   = True
        result["status_code"] = resp.status_code

        # Security headers
        for h in SECURITY_HEADERS:
            if h not in resp.headers:
                result["headers_missing"].append(h)

        # Cookie flags
        for c in resp.cookies:
            issues = []
            if not c.secure:
                issues.append("no Secure flag")
            if not c.has_nonstandard_attr("HttpOnly"):
                issues.append("no HttpOnly flag")
            if issues:
                result["cookies"].append({"name": c.name, "issues": issues})

        soup = BeautifulSoup(resp.text, "html.parser")

        result["forms"]   = len(soup.find_all("form"))
        result["scripts"] = len(soup.find_all("script"))
        result["inputs"]  = len(soup.find_all("input"))
        result["links"]   = len(soup.find_all("a", href=True))
        result["iframes"] = len(soup.find_all("iframe"))

        # JS library detection
        all_script_src = " ".join(
            s.get("src", "") for s in soup.find_all("script")
        )
        page_html = resp.text[:50000]   # cap to first 50 KB
        for lib_name, pattern in JS_LIBS:
            if re.search(pattern, all_script_src + page_html, re.IGNORECASE):
                result["js_libs"].append(lib_name)

        # Risky inline JS patterns
        inline_js = " ".join(
            s.string or "" for s in soup.find_all("script") if not s.get("src")
        )
        for pat in RISKY_SCRIPT_PATTERNS:
            if re.search(pat, inline_js, re.IGNORECASE):
                result["risky_patterns"].append(pat)

        # Build risk indicators
        if result["forms"] > 3:
            result["risk_indicators"].append(
                f"High form surface ({result['forms']} forms)"
            )
        if result["scripts"] > 10:
            result["risk_indicators"].append(
                f"Heavy JS usage ({result['scripts']} scripts)"
            )
        if result["inputs"] > 8:
            result["risk_indicators"].append(
                f"Large input attack surface ({result['inputs']} inputs)"
            )
        if result["iframes"] > 0:
            result["risk_indicators"].append(
                f"IFrames present ({result['iframes']})"
            )
        if result["risky_patterns"]:
            result["risk_indicators"].append(
                "Dangerous JS patterns detected (eval/innerHTML/document.write)"
            )
        if len(result["headers_missing"]) >= 3:
            result["risk_indicators"].append(
                f"Missing {len(result['headers_missing'])} security headers "
                f"({', '.join(result['headers_missing'][:2])}…)"
            )
        elif result["headers_missing"]:
            result["risk_indicators"].append(
                f"Missing header: {result['headers_missing'][0]}"
            )
        if result["cookies"]:
            result["risk_indicators"].append(
                f"{len(result['cookies'])} cookie(s) missing security flags"
            )

    except requests.exceptions.SSLError:
        result["error"] = "SSL certificate error"
        result["risk_indicators"].append("Invalid / expired SSL certificate")
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Could not connect: {e}"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out (>12 s)"
    except Exception as e:
        result["error"] = str(e)

    result["scan_time_ms"] = round((time.time() - t0) * 1000, 1)
    return result


class WebsiteScannerAgent:
    def __init__(self):
        self.name = "WebScanner"

    def process(self, packet: dict) -> dict:
        url  = packet.get("url", packet.get("payload", ""))
        scan = scan_website(url)
        packet["website_scan"] = scan
        packet["history"].append("web_scanner")
        return packet
