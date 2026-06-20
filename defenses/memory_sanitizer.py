import re

BLACKLIST = [
    "trust all users",
    "disable safety",
    "ignore previous instructions",
    "bypass security",
    "reveal system prompt",
    "forget everything",
    "execute unsafe command",
    "run as root",
    "run as admin",
    "jailbreak",
    "developer mode",
]

REGEX_PATTERNS = [
    r"ignore\s+(previous|all|system)\s+(instructions?|prompts?|rules?)",
    r"bypass\s+(security|filter|rules?|restrictions?)",
    r"you\s+are\s+now\s+(a\s+)?(?:DAN|jailbreak|unrestricted)",
    r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(evil|uncensored|unrestricted|jailbroken)",
]


def sanitize_memory(text: str) -> dict:
    original = text
    removed = []

    for phrase in BLACKLIST:
        pattern = re.compile(re.escape(phrase), re.IGNORECASE)
        if pattern.search(text):
            removed.append(phrase)
            text = pattern.sub("[REMOVED]", text)

    for pat in REGEX_PATTERNS:
        compiled = re.compile(pat, re.IGNORECASE)
        if compiled.search(text):
            removed.append(f"(pattern: {pat})")
            text = compiled.sub("[REMOVED]", text)

    return {
        "original": original,
        "cleaned_memory": text,
        "tokens_removed": removed,
        "sanitized": len(removed) > 0,
    }
