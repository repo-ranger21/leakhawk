# LeakHawk

> *Sees through the disguise.*

A local-first password audit tool that goes beyond "have I been pwned" —
it catches passwords that are *technically unique* but still *predictable*,
then generates strong replacements.

## Why this exists

Most password auditors stop at breach-database lookups. That misses a huge
category of risk: passwords that have never leaked but are still guessable —
`P@ssw0rd123` looks "strong" by entropy math, but any real cracking
dictionary de-leets it to `password` in the first pass.

LeakHawk adds a **deep pattern detection layer** on top of breach
checking:

- **Keyboard walks** — `qwerty123`, `1qaz2wsx`
- **Disguised common words** — leetspeak substitution doesn't fool the de-leet pass
- **Personal info bleed** — password contains your username or the site name
- **Sequential/repeated chunks** — `abc123`, `aaa111`
- **Cross-account similarity clustering** — `Summer2024!` and `Summer2025!` flagged as effectively the same password

## Zero-trust architecture

**Your passwords never leave your machine.** The only network call is to
Have I Been Pwned's k-anonymity API — and even that only sends a 5-character
hash *prefix*, never the password or full hash. See [`src/hibp.py`](src/hibp.py)
for the exact mechanism.

Everything else — parsing, pattern detection, entropy scoring, and password
generation — runs entirely locally.

## Install

```bash
pip install -r requirements.txt
```

## Usage

### 1. Export your passwords

Chrome/Edge/Brave: `chrome://settings/passwords` → ⋮ → Export passwords
Firefox: `about:logins` → ⋮ → Export Logins

### 2. Audit

```bash
python src/main.py audit passwords.csv
```

Add `--no-hibp` to run fully offline (pattern detection only, no network calls at all).

### 3. Fix

```bash
python src/main.py fix passwords.csv --output new_passwords.csv --min-risk MEDIUM
```

This audits, generates cryptographically random 10–16 character replacements
for anything at or above the specified risk level, and writes them to a CSV
you can reference while manually updating each site.

`--length` controls generated password length (10–16, default 14).

## How risk scoring works

Each entry gets a 0–100 risk score combining:

| Signal | Weight |
|---|---|
| Confirmed breached (HIBP) | +55 (+10 if breached 1000+ times) |
| Low entropy | up to +25 |
| Pattern flags (keyboard walk, sequential, etc.) | up to +24 |
| Disguised common word | +20 (defeats entropy math entirely) |
| Similar to another saved password | +15 |

Scores map to **CRITICAL / HIGH / MEDIUM / GOOD**.

## Project structure

```
src/
  main.py           CLI entry point
  importer.py       Browser CSV export parser
  hibp.py           k-anonymity breach checking
  pattern_detect.py Deep pattern detection engine (the differentiator)
  entropy.py         Strength scoring
  generator.py       Cryptographically secure password generation
  report.py          Terminal report rendering
  exporter.py         CSV export for replacements
examples/
  sample_export.csv  Test fixture
```

## Roadmap

- [ ] Web UI (client-side only, same zero-trust model — all crypto/parsing in-browser, HIBP call only)
- [ ] Real 10k-word common password list (currently a small embedded seed list)
- [ ] Password manager API integrations for one-click updates
- [ ] JSON export option for programmatic use

## Security notes

- Password generation uses Python's `secrets` module (CSPRNG), never `random`
- HIBP requests use the `Add-Padding` header to mitigate response-size side-channel analysis
- No password, hash, or personally identifying data is logged or written to disk except in files you explicitly request

## License

MIT
