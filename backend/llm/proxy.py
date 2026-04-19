class LLMProxy:
    """
    Placeholder LLM proxy.

    Replace this with a provider integration in production and keep policy
    enforcement centralized in this class.
    """

    def generate_safe_response(self, prompt: str, restrict: bool = False) -> str:
        if restrict:
            return (
                "The original request contained risky phrasing, so the gateway is "
                "providing a limited high-level response instead of executing unsafe instructions."
            )

        return f"Sanitized response for prompt: {prompt}"
