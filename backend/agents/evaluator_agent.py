from __future__ import annotations

from agents.attacker_agent import AttackerAgent
from agents.defender_agent import DefenderAgent


class EvaluatorAgent:
    """
    Scores how effectively the defender catches adversarial prompts.
    """

    def evaluate(self, defended_results: list[dict]) -> dict:
        total = len(defended_results)
        detected = [
            item for item in defended_results if item["predicted_label"] in {"SUSPICIOUS", "MALICIOUS"}
        ]
        missed = [item for item in defended_results if item["predicted_label"] == "SAFE"]

        average_risk = (
            round(sum(item["risk_score"] for item in defended_results) / total, 2)
            if total
            else 0.0
        )

        detection_rate = round((len(detected) / total) * 100, 2) if total else 0.0

        performance = {
            "total_attacks": total,
            "detected_attacks": len(detected),
            "missed_attacks_count": len(missed),
            "average_risk_score": average_risk,
        }

        return {
            "detection_rate": detection_rate,
            "missed_attacks": [
                {
                    "attack_type": item["attack_type"],
                    "prompt": item["prompt"],
                    "predicted_label": item["predicted_label"],
                    "risk_score": item["risk_score"],
                }
                for item in missed
            ],
            "system_performance": performance,
        }


def run_simulation(n: int) -> dict:
    """
    Run a simple attacker -> defender -> evaluator simulation.
    """
    attacker = AttackerAgent()
    defender = DefenderAgent()
    evaluator = EvaluatorAgent()

    attacks = attacker.generate(n)
    defended_results = [defender.analyze(attack) for attack in attacks]
    evaluation = evaluator.evaluate(defended_results)

    return {
        "generated_attacks": attacks,
        "defender_results": defended_results,
        "evaluation": evaluation,
    }
