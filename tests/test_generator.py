"""
test_generator.py — Tests for password generation.

These tests focus on correctness properties (length, charset coverage,
no accidental collisions) rather than "randomness quality," since
statistical randomness testing isn't practical in a unit test — that
guarantee comes from using `secrets` under the hood, verified by
code review, not by testing output samples.
"""

import re
import pytest
from generator import generate_password, generate_replacement_for


class TestGeneratePassword:
    def test_default_length_is_14(self):
        assert len(generate_password()) == 14

    def test_respects_custom_length(self):
        for length in [10, 12, 16]:
            assert len(generate_password(length)) == length

    def test_rejects_length_below_minimum(self):
        with pytest.raises(ValueError):
            generate_password(9)

    def test_rejects_length_above_maximum(self):
        with pytest.raises(ValueError):
            generate_password(17)

    def test_contains_lowercase(self):
        pw = generate_password(16)
        assert re.search(r"[a-z]", pw)

    def test_contains_uppercase(self):
        pw = generate_password(16)
        assert re.search(r"[A-Z]", pw)

    def test_contains_digit(self):
        pw = generate_password(16)
        assert re.search(r"[0-9]", pw)

    def test_contains_symbol(self):
        pw = generate_password(16)
        assert re.search(r"[^a-zA-Z0-9]", pw)

    def test_avoids_ambiguous_characters_by_default(self):
        # il1Lo0O are excluded by default since they're easy to
        # misread when manually transcribing a password
        ambiguous = set("il1Lo0O")
        for _ in range(20):
            pw = generate_password(16)
            assert not (set(pw) & ambiguous), f"Found ambiguous char in {pw}"

    def test_generates_different_passwords_each_call(self):
        passwords = {generate_password() for _ in range(50)}
        # With a proper CSPRNG, 50 calls should never collide
        assert len(passwords) == 50


class TestGenerateReplacementFor:
    def test_replacement_differs_from_original(self, make_entry):
        entry = make_entry("password123")
        new_pw = generate_replacement_for(entry)
        assert new_pw != entry.password

    def test_replacement_respects_length_param(self, make_entry):
        entry = make_entry("password123")
        new_pw = generate_replacement_for(entry, length=12)
        assert len(new_pw) == 12
