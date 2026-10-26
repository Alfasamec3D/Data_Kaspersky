import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import load_data
import vulncheck
from versions import matching_ranges, parse_version, compare, sort_versions

HERE = Path(__file__).parent


class VersionTests(unittest.TestCase):
    def test_parse_and_compare(self):
        self.assertEqual(parse_version("2.41.0.2"), (2, 41, 0, 2))
        self.assertEqual(compare(parse_version("7.0"), parse_version("7.0.0")), 0)
        self.assertLess(compare(parse_version("8.5.9"), parse_version("8.5.11")), 0)
        self.assertEqual(
            sort_versions(["8.5.11", "8.5.9", "8.5.100"]),
            ["8.5.9", "8.5.11", "8.5.100"],
        )

    def test_single_range(self):
        self.assertTrue(matching_ranges("9.0.10", [("9", "9.0.15")]))
        self.assertFalse(matching_ranges("9.0.15", [("9", "9.0.15")]))
        self.assertFalse(matching_ranges("8.5.0", [("9", "9.0.15")]))  # before start

    def test_branches(self):
        pg = [("0", "12.21.1"), ("0", "13.17.1"), ("0", "15.9.1")]
        self.assertTrue(matching_ranges("12.5.1", pg))
        self.assertFalse(matching_ranges("12.21.1", pg))
        self.assertFalse(matching_ranges("13.18.1", pg))  # newer its own branch
        self.assertFalse(matching_ranges("17.0.1", pg))
        git = [("0", "2.40.2"), ("0", "2.41.1"), ("0", "2.45.1")]
        self.assertTrue(matching_ranges("2.41.0.2", git))
        self.assertFalse(matching_ranges("2.46.0", git))


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = str(Path(cls.tmp.name) / "t.db")
        load_data.main(
            [
                "--db",
                cls.db,
                "--vulnerabilities",
                str(HERE / "vulnerabilities.json"),
                "--versions",
                str(HERE / "versions.json"),
            ]
        )

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_reload_is_idempotent(self):
        load_data.main(
            [
                "--db",
                self.db,
                "--vulnerabilities",
                str(HERE / "vulnerabilities.json"),
                "--versions",
                str(HERE / "versions.json"),
            ]
        )
        conn = sqlite3.connect(self.db)
        self.assertEqual(
            conn.execute("select count(*) from versions").fetchone()[0], 834
        )

    def test_info_vulnerable_and_clean(self):
        self.assertEqual(
            vulncheck.main(["--db", self.db, "info", "Git for Windows", "2.40.1"]), 1
        )
        self.assertEqual(
            vulncheck.main(["--db", self.db, "info", "Git for Windows", "2.47.1"]), 0
        )

    def test_safe_and_errors(self):
        self.assertEqual(
            vulncheck.main(["--db", self.db, "safe", "Mozilla Firefox ESR"]), 0
        )
        self.assertEqual(
            vulncheck.main(["--db", self.db, "safe", "no-such-product"]), 2
        )
        self.assertEqual(
            vulncheck.main(["--db", self.db, "safe", "Foxit"]), 2
        )  # ambiguous


if __name__ == "__main__":
    unittest.main()
