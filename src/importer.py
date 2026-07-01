"""
importer.py — Parses browser password export CSVs.

Chrome, Firefox, Edge, and Brave all export the same schema:
    name,url,username,password

This module normalizes them into a list of PasswordEntry objects.
"""

from dataclasses import dataclass, field
import csv
from pathlib import Path


@dataclass
class PasswordEntry:
    site_name: str
    url: str
    username: str
    password: str
    row_index: int
    flags: list = field(default_factory=list)
    risk_score: int = 0  # 0-100, higher = worse
    risk_level: str = "UNKNOWN"


REQUIRED_COLUMNS = {"name", "url", "username", "password"}


def load_export(csv_path: str) -> list[PasswordEntry]:
    """
    Loads a browser password export CSV into PasswordEntry objects.
    Raises ValueError if the CSV doesn't match the expected schema.
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"No file found at {csv_path}")

    entries = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = {h.strip().lower() for h in (reader.fieldnames or [])}

        if not REQUIRED_COLUMNS.issubset(headers):
            missing = REQUIRED_COLUMNS - headers
            raise ValueError(
                f"CSV missing required columns: {missing}. "
                f"Expected a standard Chrome/Firefox/Edge password export."
            )

        for i, row in enumerate(reader):
            # Normalize keys to lowercase to handle case variance across browsers
            row = {k.strip().lower(): v for k, v in row.items()}
            password = row.get("password", "")
            if not password:
                continue  # skip entries with blank passwords (nothing to audit)

            entries.append(
                PasswordEntry(
                    site_name=row.get("name", "").strip() or row.get("url", "unknown"),
                    url=row.get("url", "").strip(),
                    username=row.get("username", "").strip(),
                    password=password,
                    row_index=i,
                )
            )

    return entries
