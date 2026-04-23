from __future__ import annotations

from decision.engine import DecisionEngine
from detection.data_leakage import DataLeakageDetector
from detection.jailbreak import JailbreakDetector
from detection.prompt_injection import PromptInjectionDetector
from llm.proxy import LLMProxy


class DefenderAgent:
    """
    Runs the gateway detection and decision pipeline over adversarial prompts.
    """

    def __init__(self) -> None:
        self.engine = DecisionEngine(
            detectors=[
                PromptInjectionDetector(),
                JailbreakDetector(),
                DataLeakageDetector(),
            ],
            llm_proxy=LLMProxy(),
        )

    def analyze(self, attack: dict[str, str]) -> dict:
        result = self.engine.analyze(attack["prompt"])
        return {
            "attack_type": attack["attack_type"],
            "prompt": attack["prompt"],
            "predicted_label": result.label,
            "risk_score": result.risk_score,
            "reason": result.reason,
            "safe_response": result.safe_response,
        }
