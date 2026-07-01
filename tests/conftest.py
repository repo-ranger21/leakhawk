"""
conftest.py — Makes src/ importable from tests/ without installing the
package, and provides shared fixtures.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

import pytest
from importer import PasswordEntry


@pytest.fixture
def make_entry():
    """Factory fixture for building PasswordEntry objects in tests
    without repeating all the boilerplate fields every time."""

    def _make(password, username="user@example.com", site_name="TestSite",
              url="https://testsite.com", row_index=0):
        return PasswordEntry(
            site_name=site_name,
            url=url,
            username=username,
            password=password,
            row_index=row_index,
        )

    return _make
