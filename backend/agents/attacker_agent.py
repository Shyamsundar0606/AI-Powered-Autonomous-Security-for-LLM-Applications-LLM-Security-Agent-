from __future__ import annotations

from adversarial.attacker_agent import AttackerAgent as BaseAttackerAgent


class AttackerAgent:
    """
    Multi-agent wrapper around the adversarial red-team generator.
    """

    def __init__(self) -> None:
        self.generator = BaseAttackerAgent()

    def generate(self, n: int) -> list[dict[str, str]]:
        return self.generator.generate_attacks(n)
