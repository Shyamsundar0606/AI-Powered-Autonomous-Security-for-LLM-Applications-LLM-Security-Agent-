import re

from detection.prompt_injection import DetectionResult


class DataLeakageDetector:
    name = "data_leakage"

    def __init__(self) -> None:
        self.patterns = {
            "credential_request": ["api key", "password", "token", "secret key", "private key"],
            "sensitive_files": [".env", "config file", "credentials", "ssh key"],
            "exfiltration": ["dump database", "export secrets", "reveal confidential", "print all secrets"],
        }
        self.secret_regexes = [
            re.compile(r"sk-[a-zA-Z0-9]{20,}"),
            re.compile(r"AKIA[0-9A-Z]{16}"),
        ]

    def analyze(self, text: str) -> DetectionResult:
        lower_text = text.lower()
        matched_rules = [
            rule
            for rule, phrases in self.patterns.items()
            if any(phrase in lower_text for phrase in phrases)
        ]
        if any(pattern.search(text) for pattern in self.secret_regexes):
            matched_rules.append("embedded_secret_pattern")

        score = min(len(set(matched_rules)) * 25, 100)
        explanation = (
            "Potential sensitive data leakage indicators detected."
            if matched_rules
            else "No data leakage indicators detected."
        )
        return DetectionResult(
            detector=self.name,
            score=score,
            matched_rules=sorted(set(matched_rules)),
            explanation=explanation,
        )
