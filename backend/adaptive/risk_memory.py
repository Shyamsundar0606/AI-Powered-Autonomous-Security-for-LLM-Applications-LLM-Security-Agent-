from __future__ import annotations

import math
import re
from collections import Counter

from sqlalchemy import desc

from logstore.db import SessionLocal
from logstore.models import LogEntry


TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_.-]+")
MAX_HISTORY = 200
SIMILARITY_THRESHOLD = 0.35


def adjust_risk(user_input: str, base_score: int) -> int:
    """
    Adapt the incoming risk score using previously logged prompt patterns.

    Strategy:
    - Compare the new prompt with recent historical prompts using a lightweight
      cosine similarity over token frequencies plus keyword overlap.
    - Increase risk when similar suspicious/malicious prompts were seen before.
    - Increase risk further when very similar prompts appear repeatedly.

    The current logs table does not store a username, so repeated-attempt logic
    is approximated using repeated prompt patterns across historical requests.
    """
    normalized_prompt = _normalize_text(user_input)
    if not normalized_prompt:
        return _clamp_score(base_score)

    tokens = _tokenize(normalized_prompt)
    if not tokens:
        return _clamp_score(base_score)

    with SessionLocal() as db:
        history = (
            db.query(LogEntry)
            .order_by(desc(LogEntry.created_at), desc(LogEntry.id))
            .limit(MAX_HISTORY)
            .all()
        )

    if not history:
        return _clamp_score(base_score)

    similar_entries: list[tuple[LogEntry, float]] = []
    repeated_matches = 0
    highest_similarity = 0.0

    for entry in history:
        historical_text = _normalize_text(entry.user_input)
        if not historical_text:
            continue

        similarity = _combined_similarity(tokens, _tokenize(historical_text))
        if similarity < SIMILARITY_THRESHOLD:
            continue

        similar_entries.append((entry, similarity))
        highest_similarity = max(highest_similarity, similarity)

        if similarity >= 0.7:
            repeated_matches += 1

    if not similar_entries:
        return _clamp_score(base_score)

    boost = _calculate_similarity_boost(similar_entries, highest_similarity)
    boost += _calculate_repetition_boost(repeated_matches)

    return _clamp_score(base_score + boost)


def _calculate_similarity_boost(
    similar_entries: list[tuple[LogEntry, float]],
    highest_similarity: float,
) -> int:
    suspicious_count = sum(1 for entry, _ in similar_entries if entry.label == "SUSPICIOUS")
    malicious_count = sum(1 for entry, _ in similar_entries if entry.label == "MALICIOUS")

    boost = 0

    if malicious_count > 0:
        boost += 18
    elif suspicious_count > 0:
        boost += 10

    if highest_similarity >= 0.8:
        boost += 10
    elif highest_similarity >= 0.6:
        boost += 6
    else:
        boost += 3

    return min(boost, 30)


def _calculate_repetition_boost(repeated_matches: int) -> int:
    if repeated_matches >= 5:
        return 15
    if repeated_matches >= 3:
        return 10
    if repeated_matches >= 2:
        return 5
    return 0


def _combined_similarity(current_tokens: list[str], historical_tokens: list[str]) -> float:
    cosine = _cosine_similarity(current_tokens, historical_tokens)
    overlap = _keyword_overlap(current_tokens, historical_tokens)
    return (0.7 * cosine) + (0.3 * overlap)


def _cosine_similarity(left_tokens: list[str], right_tokens: list[str]) -> float:
    left_counts = Counter(left_tokens)
    right_counts = Counter(right_tokens)

    dot_product = sum(left_counts[token] * right_counts[token] for token in left_counts)
    left_magnitude = math.sqrt(sum(value * value for value in left_counts.values()))
    right_magnitude = math.sqrt(sum(value * value for value in right_counts.values()))

    if left_magnitude == 0 or right_magnitude == 0:
        return 0.0

    return dot_product / (left_magnitude * right_magnitude)


def _keyword_overlap(left_tokens: list[str], right_tokens: list[str]) -> float:
    left_set = set(left_tokens)
    right_set = set(right_tokens)

    if not left_set or not right_set:
        return 0.0

    intersection = len(left_set & right_set)
    union = len(left_set | right_set)
    return intersection / union if union else 0.0


def _normalize_text(value: str) -> str:
    return " ".join(value.lower().strip().split())


def _tokenize(value: str) -> list[str]:
    return [token for token in TOKEN_PATTERN.findall(value) if len(token) > 2]


def _clamp_score(score: int) -> int:
    return max(0, min(int(score), 100))
