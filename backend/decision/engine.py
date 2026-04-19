from api.schemas import AnalyzeResponse
from detection.output_filter import OutputFilter


class DecisionEngine:
    def __init__(self, detectors: list, llm_proxy) -> None:
        self.detectors = detectors
        self.llm_proxy = llm_proxy
        self.output_filter = OutputFilter()

    def analyze(self, user_input: str) -> AnalyzeResponse:
        results = [detector.analyze(user_input) for detector in self.detectors]
        highest_score = max((result.score for result in results), default=0)
        matched_rules = [rule for result in results for rule in result.matched_rules]

        if highest_score >= 75:
            label = "MALICIOUS"
        elif highest_score >= 35 or len(matched_rules) >= 2:
            label = "SUSPICIOUS"
        else:
            label = "SAFE"

        reason = self._build_reason(label, results)
        safe_response = self._build_safe_response(label, user_input)

        return AnalyzeResponse(
            risk_score=highest_score,
            label=label,
            reason=reason,
            safe_response=safe_response,
        )

    def _build_reason(self, label: str, results: list) -> str:
        active_findings = [result for result in results if result.matched_rules]
        if not active_findings:
            return "No major prompt injection, jailbreak, or data leakage patterns were detected."

        modules = ", ".join(result.detector for result in active_findings)
        return f"{label} classification triggered by findings in: {modules}."

    def _build_safe_response(self, label: str, user_input: str) -> str:
        if label == "MALICIOUS":
            return "Request blocked because it violates gateway safety policies."

        if label == "SUSPICIOUS":
            warning = "Request partially restricted due to risky instructions. Returning a minimized safe answer."
            generated = self.llm_proxy.generate_safe_response(user_input, restrict=True)
            return self.output_filter.sanitize(f"{warning} {generated}")

        generated = self.llm_proxy.generate_safe_response(user_input, restrict=False)
        return self.output_filter.sanitize(generated)
