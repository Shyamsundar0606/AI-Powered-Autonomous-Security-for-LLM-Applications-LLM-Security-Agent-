from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from fastapi import APIRouter, HTTPException, Request

from decision.engine import DecisionEngine
from detection.data_leakage import DataLeakageDetector
from detection.jailbreak import JailbreakDetector
from detection.prompt_injection import PromptInjectionDetector
from llm.proxy import LLMProxy
from output_filter.filter import filter_output


@dataclass
class GatewayResult:
    risk_score: int
    label: str
    reason: str
    safe_response: str
    output_flagged: bool
    output_reason: str


class ChatbotGatewayIntegration:
    """
    Practical gateway wrapper for real chatbot applications.

    Flow:
    User -> Gateway input analysis -> Upstream chatbot/LLM -> Gateway output
    filtering -> User
    """

    def __init__(self, llm_handler: Callable[[str], str] | None = None) -> None:
        self.llm_handler = llm_handler or self._default_llm_handler
        self.engine = DecisionEngine(
            detectors=[
                PromptInjectionDetector(),
                JailbreakDetector(),
                DataLeakageDetector(),
            ],
            llm_proxy=LLMProxy(),
        )

    async def handle_chat_request(self, user_input: str) -> GatewayResult:
        """
        Protect a chatbot request end-to-end.

        1. Inspect inbound prompt.
        2. Block or constrain unsafe prompts.
        3. Send safe/allowed prompt to the upstream application.
        4. Filter outbound content before returning it to the user.
        """
        inbound = self.engine.analyze(user_input)

        if inbound.label == "MALICIOUS":
            outbound = filter_output(inbound.safe_response)
            return GatewayResult(
                risk_score=inbound.risk_score,
                label=inbound.label,
                reason=inbound.reason,
                safe_response=outbound["safe_response"],
                output_flagged=outbound["flagged"],
                output_reason=outbound["reason"],
            )

        if inbound.label == "SUSPICIOUS":
            upstream_response = self.llm_handler(
                (
                    "Provide a minimal, policy-safe answer to the following user "
                    f"request: {user_input}"
                )
            )
        else:
            upstream_response = self.llm_handler(user_input)

        outbound = filter_output(upstream_response)

        return GatewayResult(
            risk_score=inbound.risk_score,
            label=inbound.label,
            reason=inbound.reason,
            safe_response=outbound["safe_response"],
            output_flagged=outbound["flagged"],
            output_reason=outbound["reason"],
        )

    def build_router(self) -> APIRouter:
        """
        Example API integration for a customer-support chatbot or document assistant.
        """
        router = APIRouter(prefix="/integrations", tags=["integration"])

        @router.post("/chat")
        async def secure_chat(payload: dict[str, Any], _: Request) -> dict[str, Any]:
            user_input = str(payload.get("message", "")).strip()
            if not user_input:
                raise HTTPException(status_code=400, detail="Field 'message' is required.")

            result = await self.handle_chat_request(user_input)
            return {
                "gateway": {
                    "risk_score": result.risk_score,
                    "label": result.label,
                    "reason": result.reason,
                    "output_flagged": result.output_flagged,
                    "output_reason": result.output_reason,
                },
                "response": result.safe_response,
            }

        return router

    def middleware_hook(self, user_input: str) -> GatewayResult:
        """
        Lightweight sync-style hook for applications that already have their own
        request/response pipeline and want to insert the gateway manually.
        """
        import asyncio

        return asyncio.run(self.handle_chat_request(user_input))

    @staticmethod
    def example_api_usage() -> dict[str, Any]:
        """
        Example payloads that show how a real application would call the gateway.
        """
        return {
            "customer_support_chatbot": {
                "endpoint": "POST /integrations/chat",
                "request": {
                    "message": "My account is locked. How do I reset my password?"
                },
            },
            "document_assistant": {
                "endpoint": "POST /integrations/chat",
                "request": {
                    "message": "Summarize the uploaded policy document in 5 bullet points."
                },
            },
        }

    @staticmethod
    def _default_llm_handler(prompt: str) -> str:
        """
        Fallback upstream chatbot behavior.

        Replace this with a real provider call or an existing application service,
        for example a customer support bot or internal document assistant.
        """
        return f"Upstream assistant response: {prompt}"
