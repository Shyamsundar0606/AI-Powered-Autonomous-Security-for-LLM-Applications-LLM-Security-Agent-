from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def build_email_alert_payload(incident: Any) -> dict:
    """Build an email-friendly alert payload for SOC workflows."""
    return {
        "channel": "email",
        "subject": f"[{incident.severity}] LLM Security Incident #{incident.id}",
        "body": (
            f"Incident {incident.id} was created for a {incident.label} prompt. "
            f"Severity: {incident.severity}. Attack type: {incident.attack_type}. "
            f"Risk score: {incident.risk_score}. Status: {incident.status}."
        ),
        "metadata": _base_metadata(incident),
    }


def build_slack_alert_payload(incident: Any) -> dict:
    """Build a webhook-style Slack payload without requiring network delivery."""
    summary = (
        f":rotating_light: Incident #{incident.id} | {incident.severity} | "
        f"{incident.attack_type} | risk={incident.risk_score} | status={incident.status}"
    )
    return {
        "channel": "slack",
        "text": summary,
        "attachments": [
            {
                "color": _severity_color(incident.severity),
                "fields": [
                    {"title": "Prompt Summary", "value": incident.prompt_summary, "short": False},
                    {"title": "Label", "value": incident.label, "short": True},
                    {"title": "Repeated Count", "value": str(incident.repeated_count), "short": True},
                ],
            }
        ],
        "metadata": _base_metadata(incident),
    }


def notify_incident(incident: Any) -> dict:
    """
    Produce structured alert payloads for downstream integrations.

    The project currently keeps this lightweight and offline-safe by returning
    payloads instead of attempting live delivery to SMTP or webhook providers.
    """
    return {
        "incident_id": incident.id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alerts": [
            build_email_alert_payload(incident),
            build_slack_alert_payload(incident),
        ],
    }


def _base_metadata(incident: Any) -> dict:
    return {
        "incident_id": incident.id,
        "severity": incident.severity,
        "status": incident.status,
        "attack_type": incident.attack_type,
        "risk_score": incident.risk_score,
        "timestamp": _serialize_timestamp(getattr(incident, "created_at", None)),
    }


def _severity_color(severity: str) -> str:
    return {
        "LOW": "#3fb950",
        "MEDIUM": "#d29922",
        "HIGH": "#db6d28",
        "CRITICAL": "#f85149",
    }.get(severity, "#6e7681")


def _serialize_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)
