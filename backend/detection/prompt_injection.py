from dataclasses import dataclass


@dataclass
class DetectionResult:
    detector: str
    score: int
    matched_rules: list[str]
    explanation: str


class PromptInjectionDetector:
    name = "prompt_injection"

    def __init__(self) -> None:
        self.patterns = {
            "instruction_override": ["ignore previous instructions", "forget prior directions"],
            "system_prompt_access": ["reveal system prompt", "show hidden prompt", "developer instructions"],
            "policy_bypass": ["bypass safety", "disable guardrails", "ignore all rules"],
        }

    def analyze(self, text: str) -> DetectionResult:
        lower_text = text.lower()
        matched_rules = [
            rule
            for rule, phrases in self.patterns.items()
            if any(phrase in lower_text for phrase in phrases)
        ]
        score = min(len(matched_rules) * 35, 100)
        explanation = (
            "Prompt injection indicators detected."
            if matched_rules
            else "No prompt injection indicators detected."
        )
        return DetectionResult(
            detector=self.name,
            score=score,
            matched_rules=matched_rules,
            explanation=explanation,
        )
