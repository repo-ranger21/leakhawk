"""
test_entropy.py — Tests for strength scoring and risk calculation.
"""

import pytest
from entropy import (
    estimate_pool_size,
    bits_of_entropy,
    entropy_rating,
    compute_risk_score,
    risk_level_for_score,
)


class TestPoolSizeEstimation:
    def test_lowercase_only(self):
        assert estimate_pool_size("abcdef") == 26

    def test_lowercase_and_digits(self):
        assert estimate_pool_size("abc123") == 36

    def test_all_character_classes(self):
        assert estimate_pool_size("aA1!") == 26 + 26 + 10 + 33

    def test_empty_string_returns_minimum(self):
        assert estimate_pool_size("") == 1


class TestBitsOfEntropy:
    def test_longer_password_has_more_entropy(self):
        short_bits = bits_of_entropy("abc123")
        long_bits = bits_of_entropy("abc123defg456")
        assert long_bits > short_bits

    def test_more_character_classes_increases_entropy(self):
        simple_bits = bits_of_entropy("aaaaaaaa")
        complex_bits = bits_of_entropy("aA1!aA1!")
        assert complex_bits > simple_bits


class TestEntropyRating:
    def test_very_weak_rating(self):
        assert entropy_rating(20) == "very weak"

    def test_weak_rating(self):
        assert entropy_rating(30) == "weak"

    def test_reasonable_rating(self):
        assert entropy_rating(45) == "reasonable"

    def test_strong_rating(self):
        assert entropy_rating(80) == "strong"

    def test_very_strong_rating(self):
        assert entropy_rating(150) == "very strong"


class TestRiskScoring:
    def test_breached_password_scores_critical_range(self, make_entry):
        entry = make_entry("password123")
        score = compute_risk_score(entry, [], breach_count=500, in_cluster=False)
        assert score >= 55

    def test_heavily_breached_password_scores_higher(self, make_entry):
        entry = make_entry("password123")
        light_breach = compute_risk_score(entry, [], breach_count=5, in_cluster=False)
        heavy_breach = compute_risk_score(
            entry, [], breach_count=5000, in_cluster=False
        )
        assert heavy_breach > light_breach

    def test_unbreached_strong_password_scores_low(self, make_entry):
        entry = make_entry("xK9$mQ2!vL7nZpQw")
        score = compute_risk_score(entry, [], breach_count=0, in_cluster=False)
        assert score < 20

    def test_disguised_common_word_flag_weighs_heavily(self, make_entry):
        # A long password with mixed charset "looks" strong by entropy
        # alone, but a disguised-common-word flag should push the score
        # up substantially regardless
        entry = make_entry("P@ssw0rd123456")
        flags = ["disguised common word ('password')", "sequential characters"]
        score = compute_risk_score(entry, flags, breach_count=0, in_cluster=False)
        assert score >= 20

    def test_cluster_membership_adds_risk(self, make_entry):
        entry = make_entry("Summer2024!")
        without_cluster = compute_risk_score(
            entry, [], breach_count=0, in_cluster=False
        )
        with_cluster = compute_risk_score(entry, [], breach_count=0, in_cluster=True)
        assert with_cluster > without_cluster

    def test_score_never_exceeds_100(self, make_entry):
        entry = make_entry("password")
        flags = ["flag1", "flag2", "flag3", "flag4", "flag5",
                 "disguised common word ('password')"]
        score = compute_risk_score(entry, flags, breach_count=1_000_000,
                                    in_cluster=True)
        assert score <= 100


class TestRiskLevelMapping:
    def test_critical_threshold(self):
        assert risk_level_for_score(70) == "CRITICAL"
        assert risk_level_for_score(100) == "CRITICAL"

    def test_high_threshold(self):
        assert risk_level_for_score(45) == "HIGH"
        assert risk_level_for_score(69) == "HIGH"

    def test_medium_threshold(self):
        assert risk_level_for_score(20) == "MEDIUM"
        assert risk_level_for_score(44) == "MEDIUM"

    def test_good_threshold(self):
        assert risk_level_for_score(0) == "GOOD"
        assert risk_level_for_score(19) == "GOOD"
