"""
pattern_detect.py — Deep pattern detection engine.

This is the differentiator beyond a basic HIBP lookup. It catches
passwords that are technically unique (never appeared in a breach dump)
but are still *predictable* — the difference between "random" and
"looks random."

Checks implemented:
    1. Keyboard walk detection      — qwerty123, 1qaz2wsx, etc.
    2. Leetspeak/dictionary match   — P@ssw0rd1 is still "password"
    3. Personal info bleed          — password contains username/email
    4. Sequential/repeated chunks   — abc123, aaa111
    5. Cross-account similarity     — Summer2024! vs Summer2025!
"""

import re
from difflib import SequenceMatcher
from itertools import combinations

# --- 1. Keyboard walk detection ---------------------------------------

KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

# Common vertical/diagonal keyboard zigzags — typed by alternating
# hands down two adjacent columns. These show up constantly in real
# breach corpora (1qaz2wsx, qazwsx, etc.) but never appear as a
# substring of a single horizontal row, so they need their own list.
KEYBOARD_ZIGZAGS = [
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm",
    "qazwsxedcrfvtgbyhnujm",
    "1qaz",
    "2wsx",
    "3edc",
]


def _keyboard_walks(min_len: int = 4):
    """Generates forward and reverse substrings of keyboard rows,
    plus known vertical/diagonal zigzag patterns (e.g. 1qaz2wsx) that
    don't appear in any single horizontal row."""
    walks = set()
    for row in KEYBOARD_ROWS:
        for length in range(min_len, len(row) + 1):
            for i in range(len(row) - length + 1):
                chunk = row[i:i + length]
                walks.add(chunk)
                walks.add(chunk[::-1])

    # Common vertical/diagonal zigzags typed with alternating hands —
    # these are some of the most common "looks random" passwords in
    # breach corpora precisely because they don't match a single row.
    for zigzag in KEYBOARD_ZIGZAGS:
        for length in range(min_len, len(zigzag) + 1):
            for i in range(len(zigzag) - length + 1):
                chunk = zigzag[i:i + length]
                walks.add(chunk)
                walks.add(chunk[::-1])

    return walks


_KEYBOARD_WALKS = _keyboard_walks()


def has_keyboard_walk(password: str) -> bool:
    lowered = password.lower()
    return any(walk in lowered for walk in _KEYBOARD_WALKS if len(walk) >= 4)


# --- 2. Leetspeak / common word detection -------------------------------

LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a", "$": "s", "!": "i",
})

# Small embedded common-password/word seed list. In production, swap this
# for a real wordlist (e.g. SecLists' 10k-most-common) loaded from disk.
COMMON_WORDS = {
    "password", "admin", "welcome", "letmein", "monkey", "dragon",
    "qwerty", "football", "baseball", "master", "sunshine", "princess",
    "login", "abc", "iloveyou", "trustno", "starwars", "shadow",
}


def matches_common_word(password: str):
    """Returns the matched common word if the password de-leets to one."""
    stripped = re.sub(r"[^a-zA-Z0-9@$!]", "", password).lower()
    de_leeted = stripped.translate(LEET_MAP)
    for word in COMMON_WORDS:
        if word in de_leeted:
            return word
    return None


# --- 3. Personal info bleed ---------------------------------------------

def contains_personal_info(password: str, username: str, site_name: str):
    """Checks whether the password leaks the username, email local-part,
    or site name it's protecting."""
    findings = []
    pw_lower = password.lower()

    email_local = username.split("@")[0] if "@" in username else username
    email_local = re.sub(r"[^a-zA-Z0-9]", "", email_local)  # strip dots, +tags, etc.
    if email_local and len(email_local) >= 3 and email_local.lower() in pw_lower:
        findings.append("contains username/email")

    site_clean = re.sub(r"[^a-zA-Z]", "", site_name).lower()
    if site_clean and len(site_clean) >= 4 and site_clean in pw_lower:
        findings.append("contains site name")

    return findings


# --- 4. Sequential / repeated chunk detection ----------------------------

def has_sequential_chars(password: str, run_len: int = 3) -> bool:
    """Catches abc, 123, cba, 321 style runs."""
    for i in range(len(password) - run_len + 1):
        chunk = password[i:i + run_len]
        codes = [ord(c.lower()) for c in chunk]
        if all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1)):
            return True
        if all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1)):
            return True
    return False


def has_repeated_chunk(password: str, chunk_len: int = 2) -> bool:
    """Catches aaaa, abab, 1212 style repetition."""
    for i in range(len(password) - chunk_len * 2 + 1):
        chunk = password[i:i + chunk_len]
        next_chunk = password[i + chunk_len:i + chunk_len * 2]
        if chunk == next_chunk:
            return True
    return False


# --- 5. Cross-account similarity clustering -------------------------------

def find_similar_clusters(entries, threshold: float = 0.75):
    """
    Groups entries whose passwords are similar enough to indicate a
    shared base pattern (e.g. Summer2024! / Summer2025!). Returns
    clusters as lists of row_index values.

    Uses SequenceMatcher ratio rather than exact match so it catches
    "same password with a digit changed," not just literal reuse.
    """
    n = len(entries)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        parent[find(x)] = find(y)

    for i, j in combinations(range(n), 2):
        ratio = SequenceMatcher(None, entries[i].password, entries[j].password).ratio()
        if ratio >= threshold:
            union(i, j)

    clusters = {}
    for i in range(n):
        root = find(i)
        clusters.setdefault(root, []).append(entries[i].row_index)

    return [c for c in clusters.values() if len(c) > 1]


# --- Orchestration ---------------------------------------------------------

def analyze_entry(entry):
    """Runs all single-entry pattern checks and returns a list of flags."""
    flags = []

    if has_keyboard_walk(entry.password):
        flags.append("keyboard-walk pattern")

    common = matches_common_word(entry.password)
    if common:
        flags.append(f"disguised common word ('{common}')")

    personal = contains_personal_info(entry.password, entry.username, entry.site_name)
    flags.extend(personal)

    if has_sequential_chars(entry.password):
        flags.append("sequential characters")

    if has_repeated_chunk(entry.password):
        flags.append("repeated character chunk")

    return flags
