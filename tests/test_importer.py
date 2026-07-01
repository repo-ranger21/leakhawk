"""
test_importer.py — Tests for browser password export CSV parsing.
"""

import pytest
from importer import load_export


class TestLoadExport:
    def test_loads_valid_csv(self, tmp_path):
        csv_content = (
            "name,url,username,password\n"
            "GitHub,https://github.com,chris@email.com,P@ssw0rd123\n"
        )
        csv_file = tmp_path / "passwords.csv"
        csv_file.write_text(csv_content)

        entries = load_export(str(csv_file))

        assert len(entries) == 1
        assert entries[0].site_name == "GitHub"
        assert entries[0].password == "P@ssw0rd123"

    def test_raises_on_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_export("/nonexistent/path.csv")

    def test_raises_on_missing_required_columns(self, tmp_path):
        csv_content = "name,url\nGitHub,https://github.com\n"
        csv_file = tmp_path / "bad.csv"
        csv_file.write_text(csv_content)

        with pytest.raises(ValueError):
            load_export(str(csv_file))

    def test_skips_entries_with_blank_password(self, tmp_path):
        csv_content = (
            "name,url,username,password\n"
            "GitHub,https://github.com,chris@email.com,\n"
            "Netflix,https://netflix.com,chris@email.com,realpassword\n"
        )
        csv_file = tmp_path / "passwords.csv"
        csv_file.write_text(csv_content)

        entries = load_export(str(csv_file))

        assert len(entries) == 1
        assert entries[0].site_name == "Netflix"

    def test_handles_case_insensitive_headers(self, tmp_path):
        csv_content = (
            "Name,URL,Username,Password\n"
            "GitHub,https://github.com,chris@email.com,P@ssw0rd123\n"
        )
        csv_file = tmp_path / "passwords.csv"
        csv_file.write_text(csv_content)

        entries = load_export(str(csv_file))

        assert len(entries) == 1

    def test_handles_utf8_bom(self, tmp_path):
        # Windows-exported CSVs often have a UTF-8 BOM at the start
        csv_content = (
            "name,url,username,password\n"
            "GitHub,https://github.com,chris@email.com,P@ssw0rd123\n"
        )
        csv_file = tmp_path / "passwords.csv"
        csv_file.write_bytes(b"\xef\xbb\xbf" + csv_content.encode("utf-8"))

        entries = load_export(str(csv_file))

        assert len(entries) == 1
        assert entries[0].site_name == "GitHub"

    def test_row_index_assigned_correctly(self, tmp_path):
        csv_content = (
            "name,url,username,password\n"
            "A,https://a.com,u,pw1\n"
            "B,https://b.com,u,pw2\n"
            "C,https://c.com,u,pw3\n"
        )
        csv_file = tmp_path / "passwords.csv"
        csv_file.write_text(csv_content)

        entries = load_export(str(csv_file))

        assert [e.row_index for e in entries] == [0, 1, 2]
