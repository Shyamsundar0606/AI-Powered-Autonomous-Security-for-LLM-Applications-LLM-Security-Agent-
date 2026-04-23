from __future__ import annotations

import json
from pathlib import Path

from decision.engine import DecisionEngine
from detection.data_leakage import DataLeakageDetector
from detection.jailbreak import JailbreakDetector
from detection.prompt_injection import PromptInjectionDetector
from llm.proxy import LLMProxy


SUPPORTED_LABELS = ("SAFE", "SUSPICIOUS", "MALICIOUS")


def evaluate_system(dataset_path: str) -> dict:
    """
    Evaluate the gateway's current detection pipeline against a labeled dataset.

    Expected dataset format:
    [
      {"prompt": "...", "label": "MALICIOUS"},
      {"prompt": "...", "label": "SAFE"}
    ]
    """
    dataset = _load_dataset(dataset_path)
    engine = _build_engine()

    total = 0
    correct = 0
    true_positive = 0
    false_positive = 0
    false_negative = 0
    confusion_matrix = _empty_confusion_matrix()

    for record in dataset:
        prompt = record["prompt"]
        actual = _normalize_label(record["label"])

        prediction = engine.analyze(prompt)
        predicted = _normalize_label(prediction.label)

        total += 1
        if predicted == actual:
            correct += 1

        confusion_matrix[actual][predicted] += 1

        actual_positive = actual != "SAFE"
        predicted_positive = predicted != "SAFE"

        if actual_positive and predicted_positive:
            true_positive += 1
        elif not actual_positive and predicted_positive:
            false_positive += 1
        elif actual_positive and not predicted_positive:
            false_negative += 1

    accuracy = (correct / total) if total else 0.0
    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive)
        else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative)
        else 0.0
    )

    return {
        "samples": total,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "confusion_matrix": confusion_matrix,
    }


def _build_engine() -> DecisionEngine:
    return DecisionEngine(
        detectors=[
            PromptInjectionDetector(),
            JailbreakDetector(),
            DataLeakageDetector(),
        ],
        llm_proxy=LLMProxy(),
    )


def _load_dataset(dataset_path: str) -> list[dict[str, str]]:
    path = Path(dataset_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, list):
        raise ValueError("Benchmark dataset must be a JSON list of prompt-label records.")

    dataset: list[dict[str, str]] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"Dataset record at index {index} must be an object.")

        prompt = item.get("prompt")
        label = item.get("label")

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError(f"Dataset record at index {index} has an invalid prompt.")
        if not isinstance(label, str):
            raise ValueError(f"Dataset record at index {index} has an invalid label.")

        dataset.append({"prompt": prompt.strip(), "label": _normalize_label(label)})

    return dataset


def _normalize_label(label: str) -> str:
    normalized = label.strip().upper()
    if normalized not in SUPPORTED_LABELS:
        raise ValueError(
            f"Unsupported label '{label}'. Expected one of: {', '.join(SUPPORTED_LABELS)}."
        )
    return normalized


def _empty_confusion_matrix() -> dict[str, dict[str, int]]:
    return {
        actual: {predicted: 0 for predicted in SUPPORTED_LABELS}
        for actual in SUPPORTED_LABELS
    }
