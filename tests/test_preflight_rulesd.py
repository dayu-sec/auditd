#!/usr/bin/env python3
"""Fixture tests for scripts/preflight-rulesd.sh (read-only rules.d scan)."""

import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "scripts" / "preflight-rulesd.sh"

DAYU_RULES = """-D
-b 8192
-f 1
-a always,exit -F arch=b64 -S execve -F auid!=unset -k process_creation_user
-w /etc/passwd -p wa -k etcpasswd
-w /usr/bin/curl -p x -k net-tool-exec
"""
PRIVILEGED_RULES = """-a always,exit -F arch=b64 -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged
"""


class PreflightRulesdTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "rules.d"
        self.dir.mkdir()

    def write(self, name, content):
        (self.dir / name).write_text(content, encoding="utf-8")

    def run_tool(self, *args):
        return subprocess.run(["bash", str(TOOL), *args], capture_output=True, text=True)

    def test_clean_layout_passes(self):
        self.write("99-dayu.rules", DAYU_RULES)
        self.write("99-privileged.rules", PRIVILEGED_RULES)
        result = self.run_tool(str(self.dir))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("0 blocker(s)", result.stdout)

    def test_minus_d_after_rules_is_a_blocker(self):
        # 98 sorts before 99: the privileged rules are added first and then
        # deleted by the -D inside the dayu file.
        self.write("98-privileged.rules", PRIVILEGED_RULES)
        self.write("99-dayu.rules", DAYU_RULES)
        result = self.run_tool(str(self.dir))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("BLOCKER", result.stdout)
        self.assertIn("98-privileged.rules", result.stdout)
        self.assertIn("99-dayu.rules", result.stdout)

    def test_identical_watch_across_files_is_a_blocker(self):
        self.write("99-dayu.rules", DAYU_RULES)
        self.write("sdm2.0.rules", "-w /usr/bin/curl -p x -k net-tool-exec\n")
        result = self.run_tool(str(self.dir))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("Rule exists", result.stdout)
        self.assertIn("sdm2.0.rules", result.stdout)

    def test_trailing_slash_duplicate_is_still_identical(self):
        self.write("99-dayu.rules", DAYU_RULES)
        self.write("sdm2.0.rules", "-w /usr/bin/curl/ -p x -k net-tool-exec\n")
        result = self.run_tool(str(self.dir))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("Rule exists", result.stdout)

    def test_same_watch_different_keys_is_only_a_warning(self):
        # Verified on the target kernel: different keys coexist (2 rules loaded).
        self.write("99-dayu.rules", DAYU_RULES)
        self.write("sdm2.0.rules", "-w /etc/passwd -p wa -k account-change\n")
        result = self.run_tool(str(self.dir))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("WARN", result.stdout)
        self.assertIn("account-change", result.stdout)

    def test_permutation_of_permissions_is_the_same_watch(self):
        self.write("99-dayu.rules", DAYU_RULES)
        self.write("sdm2.0.rules", "-w /etc/passwd -p aw -k etcpasswd\n")
        result = self.run_tool(str(self.dir))
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_ignore_errors_flag_warns_without_blocking(self):
        self.write("99-dayu.rules", DAYU_RULES + "-i\n")
        result = self.run_tool(str(self.dir))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("-i", result.stdout)
        self.assertIn("WARN", result.stdout)

    def test_empty_directory_passes(self):
        result = self.run_tool(str(self.dir))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("no .rules files", result.stdout)

    def test_missing_directory_is_a_usage_error(self):
        result = self.run_tool(str(Path(self.tmp.name) / "absent"))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("not a directory", result.stderr)


if __name__ == "__main__":
    unittest.main()
