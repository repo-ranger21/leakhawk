"""
exporter.py — Writes updated passwords back out in browser-importable
CSV format (name,url,username,password), so the user can re-import
into Chrome/Firefox/Edge after manually updating each site.
"""

import csv


def export_replacements(pairs, output_path: str) -> None:
    """pairs: list of (entry, new_password) tuples."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "url", "username", "password"])
        for entry, new_pw in pairs:
            writer.writerow([entry.site_name, entry.url, entry.username, new_pw])


def export_full_report(entries, output_path: str) -> None:
    """Writes the full audit (all entries, all risk data) to CSV for
    record-keeping — does NOT include plaintext passwords by default."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["site", "username", "risk_level", "risk_score", "breached_count", "flags"])
        for e in entries:
            writer.writerow([
                e.site_name,
                e.username,
                e.risk_level,
                e.risk_score,
                getattr(e, "breach_count", "unknown"),
                "; ".join(e.flags),
            ])
