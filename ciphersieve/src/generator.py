"""
generator.py — Cryptographically secure password generation.

Uses the `secrets` module (CSPRNG, backed by the OS's cryptographic
random source) rather than `random`, which is deterministic and
predictable given enough output — fine for simulations, unsafe for
anything security-related.
"""

import secrets
import string

AMBIGUOUS_CHARS = "il1Lo0O"


def generate_password(length: int = 14, avoid_ambiguous: bool = True) -> str:
    """
    Generates a cryptographically random password of the given length
    (10-16 recommended), guaranteeing at least one character from each
    required pool: lowercase, uppercase, digit, symbol.
    """
    if not (10 <= length <= 16):
        raise ValueError("length must be between 10 and 16")

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{};:,.?"

    if avoid_ambiguous:
        lowercase = "".join(c for c in lowercase if c not in AMBIGUOUS_CHARS)
        uppercase = "".join(c for c in uppercase if c not in AMBIGUOUS_CHARS)
        digits = "".join(c for c in digits if c not in AMBIGUOUS_CHARS)

    pools = [lowercase, uppercase, digits, symbols]
    all_chars = "".join(pools)

    # Guarantee representation from every pool, then fill the rest randomly
    password_chars = [secrets.choice(pool) for pool in pools]
    password_chars += [secrets.choice(all_chars) for _ in range(length - len(pools))]

    # Shuffle securely so the guaranteed chars aren't always in the same position
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def generate_replacement_for(entry, length: int = 14) -> str:
    """Generates a replacement password for a flagged entry, ensuring
    the new password doesn't accidentally collide with the old one."""
    new_password = generate_password(length)
    while new_password == entry.password:
        new_password = generate_password(length)
    return new_password
