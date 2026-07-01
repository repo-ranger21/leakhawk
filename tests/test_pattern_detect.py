"""
test_pattern_detect.py — Tests for the deep pattern detection engine.

This is the most important test file in the suite since pattern
detection is LeakHawk's differentiator over plain HIBP lookups.
"""

import pytest
from pattern_detect import (
    has_keyboard_walk,
    matches_common_word,
    contains_personal_info,
    has_sequential_chars,
    has_repeated_chunk,
    find_similar_clusters,
    analyze_entry,
)


class TestKeyboardWalk:
    def test_detects_qwerty_row(self):
        assert has_keyboard_walk("qwerty123") is True

    def test_detects_reversed_walk(self):
        assert has_keyboard_walk("9876trewq") is True

    def test_detects_number_row_walk(self):
        assert has_keyboard_walk("1qaz2wsx") is True

    def test_ignores_random_strong_password(self):
        assert has_keyboard_walk("xK9$mQ2!vL7nZp") is False

    def test_case_insensitive(self):
        assert has_keyboard_walk("QWERTY123") is True

    def test_short_password_no_false_positive(self):
        # Substrings shorter than the walk threshold shouldn't trigger
        assert has_keyboard_walk("qw") is False


class TestCommonWordDetection:
    def test_detects_plain_password(self):
        assert matches_common_word("password") == "password"

    def test_detects_leetspeak_substitution(self):
        result = matches_common_word("P@ssw0rd123")
        assert result == "password"

    def test_detects_word_embedded_in_longer_string(self):
        assert matches_common_word("xxqwertyxx") == "qwerty"

    def test_ignores_random_string(self):
        assert matches_common_word("xK9mQ2vL7nZp") is None

    def test_case_insensitive(self):
        assert matches_common_word("PASSWORD") == "password"


class TestPersonalInfoBleed:
    def test_detects_username_in_password(self):
        findings = contains_personal_info("chrisdev123", "chrisdev", "site")
        assert "contains username/email" in findings

    def test_detects_email_local_part(self):
        findings = contains_personal_info(
            "chrispeterson99", "chris.peterson@email.com", "site"
        )
        assert "contains username/email" in findings

    def test_detects_site_name_in_password(self):
        findings = contains_personal_info("mynetflix2024", "user", "Netflix")
        assert "contains site name" in findings

    def test_no_false_positive_on_unrelated_password(self):
        findings = contains_personal_info("xK9$mQ2!vL7nZp", "chrisdev", "Netflix")
        assert findings == []

    def test_short_username_not_flagged(self):
        # Very short usernames (< 3 chars) shouldn't trigger false positives
        # since they're too likely to appear coincidentally
        findings = contains_personal_info("password123", "ab", "site")
        assert "contains username/email" not in findings


class TestSequentialAndRepeatedChunks:
    def test_detects_ascending_sequence(self):
        assert has_sequential_chars("abc123") is True

    def test_detects_descending_sequence(self):
        assert has_sequential_chars("cba321") is True

    def test_ignores_non_sequential(self):
        assert has_sequential_chars("xK9mQ2vL") is False

    def test_detects_repeated_chunk(self):
        assert has_repeated_chunk("abab1212") is True

    def test_detects_quadruple_repeat(self):
        assert has_repeated_chunk("aaaa") is True

    def test_ignores_non_repeated(self):
        assert has_repeated_chunk("xK9mQ2vL") is False


class TestSimilarityClustering:
    def test_clusters_similar_passwords(self, make_entry):
        entries = [
            make_entry("Summer2024!", row_index=0),
            make_entry("Summer2025!", row_index=1),
            make_entry("xK9$mQ2!vL7nZp", row_index=2),
        ]
        clusters = find_similar_clusters(entries, threshold=0.75)
        assert len(clusters) == 1
        assert set(clusters[0]) == {0, 1}

    def test_no_clusters_when_all_unique(self, make_entry):
        entries = [
            make_entry("xK9$mQ2!vL7nZp", row_index=0),
            make_entry("qR4#wT8&hN2mBx", row_index=1),
            make_entry("zY6@pL9!fD3kWv", row_index=2),
        ]
        clusters = find_similar_clusters(entries, threshold=0.75)
        assert clusters == []

    def test_identical_passwords_cluster(self, make_entry):
        entries = [
            make_entry("SamePassword123", row_index=0),
            make_entry("SamePassword123", row_index=1),
        ]
        clusters = find_similar_clusters(entries, threshold=0.75)
        assert len(clusters) == 1
        assert set(clusters[0]) == {0, 1}


class TestAnalyzeEntry:
    def test_flags_multiple_issues_on_weak_password(self, make_entry):
        # "qwerty123" is a keyboard walk, contains "qwerty" as a common
        # word, and has a sequential run in "123"
        entry = make_entry("qwerty123", username="chrisp")
        flags = analyze_entry(entry)
        assert any("keyboard-walk" in f for f in flags)
        assert any("qwerty" in f for f in flags)
        assert any("sequential" in f for f in flags)

    def test_clean_password_has_no_flags(self, make_entry):
        entry = make_entry("xK9$mQ2!vL7nZp", username="chrisp")
        flags = analyze_entry(entry)
        assert flags == []

    def test_disguised_password_still_caught(self, make_entry):
        entry = make_entry("P@ssw0rd123")
        flags = analyze_entry(entry)
        assert any("disguised common word" in f for f in flags)
