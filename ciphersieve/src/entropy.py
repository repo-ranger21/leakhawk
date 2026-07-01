"""
entropy.py — Password strength scoring.

Computes Shannon-style entropy based on character pool size and length,
then combines it with pattern flags and breach status into a single
0-100 risk score used for the final report.
"""

import math

CHAR_POOLS = [
    (r"[a-z]", 26),
    (r"[A-Z]", 26),
    (r"[0-9]", 10),
    (r"[^a-zA-Z0-9]", 33),  # rough symbol pool estimate
]

import re


def estimate_pool_size(password: str) -> int:
    pool = 0
    for pattern, size in CHAR_POOLS:
        if re.search(pattern, password):
            pool += size
    return pool or 1


def bits_of_entropy(password: str) -> float:
    """log2(pool_size ^ length) = length * log2(pool_size)."""
    pool = estimate_pool_size(password)
    return len(password) * math.log2(pool)


def entropy_rating(bits: float) -> str:
    if bits < 28:
        return "very weak"
    if bits < 36:
        return "weak"
    if bits < 60:
        return "reasonable"
    if bits < 128:
        return "strong"
    return "very strong"


def compute_risk_score(entry, pattern_flags: list, breach_count: int, in_cluster: bool) -> int:
    """
    Combines all signals into a single 0-100 risk score.
    Higher = worse. This is deliberately front-loaded on breach status
    since a confirmed-leaked password is a categorically different risk
    than a merely-weak one.
    """
    score = 0

    # Breach status dominates the score
    if breach_count > 0:
        score += 55
        if breach_count > 1000:
            score += 10  # extremely common breached password

    # Entropy contribution (inverse — low entropy = high risk)
    bits = bits_of_entropy(entry.password)
    if bits < 28:
        score += 25
    elif bits < 36:
        score += 18
    elif bits < 60:
        score += 8

    # Pattern flags — each one adds risk, capped contribution
    score += min(len(pattern_flags) * 6, 24)

    # A disguised common word defeats entropy math entirely (crackers
    # de-leet as a standard first pass) — weight it heavily regardless
    # of how "strong" the raw entropy score looks
    if any("disguised common word" in f for f in pattern_flags):
        score += 20

    # Reuse/similarity cluster membership
    if in_cluster:
        score += 15

    return min(score, 100)


def risk_level_for_score(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "GOOD"
