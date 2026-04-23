from __future__ import annotations

import re


SECRET_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)\b(api[_ -]?key)\b\s*[:=]?\s*[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)\b(password|passwd|pwd|secret|token)\b\s*[:=]?\s*\S+"),
    re.compile(r"(?i)\b(private[_ -]?key)\b\s*[:=]?\s*.+"),
]

SYSTEM_PROMPT_PATTERNS = [
    re.compile(r"(?i)\bsystem prompt\b"),
    re.compile(r"(?i)\bdeveloper instructions?\b"),
    re.compile(r"(?i)\bhidden instructions?\b"),
    re.compile(r"(?i)\binternal policy\b"),
    re.compile(r"(?i)\byou are chatgpt\b"),
]

UNSAFE_CONTENT_PATTERNS = [
    re.compile(r"(?i)\bhow to build (?:a|an) bomb\b"),
    re.compile(r"(?i)\bhow to make explosives?\b"),
    re.compile(r"(?i)\bsteal credentials\b"),
    re.compile(r"(?i)\bexfiltrat(?:e|ion)\b"),
    re.compile(r"(?i)\bdisable security controls?\b"),
    re.compile(r"(?i)\bdeploy malware\b"),
]


def filter_output(response: str) -> dict:
    """
    Analyze an LLM response for sensitive or unsafe content.

    Behavior:
    - Redact secrets when masking is sufficient.
    - Block responses that leak system prompts or contain clearly unsafe content.
    - Return a structured decision for downstream callers.
    """
    normalized = response or ""
    flagged_reasons: list[str] = []

    redacted_response = normalized
    secret_detected = False

    for pattern in SECRET_PATTERNS:
        if pattern.search(redacted_response):
            secret_detected = True
            redacted_response = pattern.sub("[REDACTED]", redacted_response)

    if secret_detected:
        flagged_reasons.append("Sensitive credentials or secrets detected and masked.")

    system_leak_detected = any(pattern.search(normalized) for pattern in SYSTEM_PROMPT_PATTERNS)
    if system_leak_detected:
        flagged_reasons.append("System prompt or internal instruction leakage detected.")

    unsafe_content_detected = any(pattern.search(normalized) for pattern in UNSAFE_CONTENT_PATTERNS)
    if unsafe_content_detected:
        flagged_reasons.append("Unsafe content detected in model response.")

    should_block = system_leak_detected or unsafe_content_detected

    if should_block:
        return {
            "safe_response": (
                "Response blocked because it contained sensitive internal instructions "
                "or unsafe content."
            ),
            "flagged": True,
            "reason": " ".join(flagged_reasons).strip(),
        }

    if flagged_reasons:
        return {
            "safe_response": redacted_response,
            "flagged": True,
            "reason": " ".join(flagged_reasons).strip(),
        }

    return {
        "safe_response": normalized,
        "flagged": False,
        "reason": "No sensitive or unsafe output patterns detected.",
    }
