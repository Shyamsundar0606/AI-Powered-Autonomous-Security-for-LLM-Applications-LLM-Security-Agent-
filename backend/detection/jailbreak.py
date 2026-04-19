from detection.prompt_injection import DetectionResult


class JailbreakDetector:
    name = "jailbreak"

    def __init__(self) -> None:
        self.patterns = {
            "unrestricted_mode": ["dan mode", "developer mode", "unfiltered mode"],
            "role_coercion": ["pretend you are not bound", "act without restrictions", "no ethical limits"],
            "rule_evasion": ["answer no matter what", "ignore safety policy", "respond without refusing"],
        }

    def analyze(self, text: str) -> DetectionResult:
        lower_text = text.lower()
        matched_rules = [
            rule
            for rule, phrases in self.patterns.items()
            if any(phrase in lower_text for phrase in phrases)
        ]
        score = min(len(matched_rules) * 30, 100)
        explanation = (
            "Jailbreak indicators detected."
            if matched_rules
            else "No jailbreak indicators detected."
        )
        return DetectionResult(
            detector=self.name,
            score=score,
            matched_rules=matched_rules,
            explanation=explanation,
        )
