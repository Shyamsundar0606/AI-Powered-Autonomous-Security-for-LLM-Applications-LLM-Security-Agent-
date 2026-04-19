import re


class OutputFilter:
    """Redacts simple secret-like patterns before content leaves the gateway."""

    def __init__(self) -> None:
        self.redaction_patterns = [
            re.compile(r"sk-[a-zA-Z0-9]{20,}"),
            re.compile(r"AKIA[0-9A-Z]{16}"),
            re.compile(r"(?i)password\s*[:=]\s*\S+"),
        ]

    def sanitize(self, text: str) -> str:
        sanitized = text
        for pattern in self.redaction_patterns:
            sanitized = pattern.sub("[REDACTED]", sanitized)
        return sanitized
