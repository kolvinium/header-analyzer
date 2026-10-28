import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "analyzer.py"


def run(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, cwd=ROOT,
    )


class TestAnalyzer(unittest.TestCase):
    def test_clean_email_has_no_flags(self):
        r = run("samples/clean.eml")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SPF: pass", r.stdout)
        self.assertIn("Red flags:\n  none", r.stdout)

    def test_route_is_oldest_first(self):
        out = run("samples/clean.eml").stdout
        self.assertLess(out.index("from laptop.local"), out.index("from mail.example.com"))

    def test_spoofed_email_is_flagged(self):
        out = run("samples/spoofed.eml").stdout
        self.assertIn("SPF: fail", out)
        self.assertIn("differs from Return-Path", out)
        self.assertIn("differs from Reply-To", out)

    def test_missing_file_exits_cleanly(self):
        r = run("samples/does-not-exist.eml")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("Traceback", r.stderr)

    def test_no_argument_prints_usage(self):
        r = run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("Usage", r.stdout)


if __name__ == "__main__":
    unittest.main()
