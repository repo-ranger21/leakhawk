"""
hibp.py — Checks passwords against Have I Been Pwned using k-anonymity.

How it works (and why it's safe):
    1. SHA-1 hash the password locally.
    2. Send only the FIRST 5 characters of the hash to HIBP.
    3. HIBP returns every hash suffix that starts with that prefix
       (usually several hundred).
    4. We compare the full hash locally against that list.

The full password — and even the full hash — never leaves this machine.
Only a 5-character prefix shared by hundreds of thousands of other
hashes goes over the network. HIBP has no way to know which exact
password you checked.
"""

import hashlib
import requests
import time

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def check_password_breached(password: str, retries: int = 2) -> int:
    """
    Returns the number of times this password has appeared in known
    breaches, or 0 if not found. Returns -1 if the check failed
    (network issue) so callers can distinguish "safe" from "unknown".
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    for attempt in range(retries + 1):
        try:
            resp = requests.get(
                HIBP_RANGE_URL.format(prefix=prefix),
                headers={"Add-Padding": "true"},  # mitigates response-size side-channel
                timeout=8,
            )
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line_suffix, count = line.split(":")
                if line_suffix == suffix:
                    return int(count)
            return 0
        except requests.RequestException:
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            return -1


def batch_check(entries, on_progress=None) -> None:
    """
    Runs breach checks across a list of PasswordEntry objects, mutating
    them in place with a 'breach_count' attribute. Deduplicates identical
    passwords so we don't hit the API twice for reused passwords.
    """
    cache: dict[str, int] = {}
    for i, entry in enumerate(entries):
        if entry.password not in cache:
            cache[entry.password] = check_password_breached(entry.password)
        entry.breach_count = cache[entry.password]
        if on_progress:
            on_progress(i + 1, len(entries))
