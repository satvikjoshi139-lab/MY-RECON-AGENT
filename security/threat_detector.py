import re

# (pattern, penalty, category, label)
ATTACK_PATTERNS = [
    # Prompt Injection
    (r"ignore\s+(previous|all|system)\s+(instructions?|prompts?|rules?)", 30, "prompt_injection", "Prompt Injection"),
    (r"forget\s+(everything|all|your\s+instructions)", 30, "prompt_injection", "Prompt Injection"),
    (r"you\s+are\s+now\s+(a\s+)?(?:DAN|jailbreak|unrestricted)", 35, "prompt_injection", "Prompt Injection"),
    (r"bypass\s+security", 25, "prompt_injection", "Prompt Injection"),
    (r"disable\s+safety", 25, "prompt_injection", "Prompt Injection"),
    (r"override\s+(your\s+)?(guidelines|instructions|rules|constraints)", 30, "prompt_injection", "Prompt Injection"),
    (r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(evil|uncensored|unrestricted|jailbroken)", 35, "prompt_injection", "Prompt Injection"),
    # Jailbreak
    (r"\bDAN\b", 35, "jailbreak", "Jailbreak"),
    (r"jailbreak", 35, "jailbreak", "Jailbreak"),
    (r"do\s+anything\s+now", 35, "jailbreak", "Jailbreak"),
    (r"developer\s+mode", 20, "jailbreak", "Jailbreak"),
    (r"unlock\s+(restricted|hidden|secret)\s+mode", 30, "jailbreak", "Jailbreak"),
    # Exfiltration
    (r"reveal\s+(hidden|system|secret|internal)", 30, "exfiltration", "Data Exfiltration"),
    (r"show\s+me\s+(your\s+)?(system\s+prompt|instructions|config)", 25, "exfiltration", "Data Exfiltration"),
    (r"print\s+(your\s+)?(system\s+prompt|instructions)", 25, "exfiltration", "Data Exfiltration"),
    # Memory Poisoning
    (r"trust\s+all\s+users", 20, "memory_poison", "Memory Poisoning"),
    (r"remember\s+that\s+.{0,30}(admin|root|privileged)", 20, "memory_poison", "Memory Poisoning"),
    # Tool Hijacking
    (r"execute\s+unsafe\s+command", 30, "tool_hijack", "Tool Hijacking"),
    (r"run\s+as\s+(root|admin|superuser)", 25, "tool_hijack", "Tool Hijacking"),
]


def analyze_threats(text: str) -> dict:
    """
    Analyse text for known attack patterns.
    Returns score (0-100), decision, and categorised threats.
    """
    score = 100
    detected = []
    categories_hit = set()

    for pattern, penalty, category, label in ATTACK_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            score -= penalty
            categories_hit.add(category)
            detected.append({
                "label": label,
                "category": category,
                "penalty": penalty,
            })

    score = max(score, 0)

    if score >= 80:
        decision = "ALLOW"
        risk_level = "LOW"
    elif score >= 50:
        decision = "SANITIZE"
        risk_level = "MEDIUM"
    else:
        decision = "BLOCK"
        risk_level = "HIGH"

    threat_summary = {}
    for cat in ["prompt_injection", "jailbreak", "exfiltration", "memory_poison", "tool_hijack"]:
        threat_summary[cat] = cat in categories_hit

    return {
        "score": score,
        "decision": decision,
        "risk_level": risk_level,
        "detected_patterns": detected,
        "threat_count": len(detected),
        "threat_summary": threat_summary,
        "categories_hit": list(categories_hit),
    }
