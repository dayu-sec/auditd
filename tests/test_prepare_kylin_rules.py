#!/usr/bin/env python3
"""Fixture tests for scripts/prepare-kylin-rules.py.

Every case runs the generator as a subprocess against a synthetic sysroot:
fake /etc/os-release, /proc/cmdline, /etc/login.defs, stub auditctl/ausyscall
binaries and independent x86_64/i386/aarch64/arm syscall tables. No host
audit state is touched.
"""

import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "scripts" / "prepare-kylin-rules.py"
BASELINE = REPO / "audit.rules"


def load_generator():
    spec = importlib.util.spec_from_file_location("prepare_kylin_rules_under_test", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Active syscall names in audit.rules. "all" is a pseudo name and openat2 is
# deliberately absent from every table: libaudit 3.0 predates openat2 and the
# Kylin 4.19 kernels answer it with ENOSYS.
MODERN_SYSCALLS = [
    "acct", "adjtimex", "bind", "bpf", "chmod", "chown", "clock_settime",
    "connect", "delete_module", "execve", "execveat", "fchmod", "fchmodat",
    "fchown", "fchownat", "finit_module", "fremovexattr", "fsconfig",
    "fsetxattr", "fsmount", "fsopen", "futimesat", "init_module",
    "io_uring_setup", "kexec_file_load", "lchown", "lremovexattr",
    "lsetxattr", "memfd_create", "mknod", "mknodat", "mount", "move_mount",
    "open", "open_by_handle_at", "open_tree", "openat", "pivot_root",
    "process_vm_readv", "process_vm_writev", "ptrace", "reboot",
    "removexattr", "rename", "renameat", "renameat2", "rmdir",
    "setdomainname", "sethostname", "setns", "setsockopt", "settimeofday",
    "setxattr", "socket", "swapoff", "swapon", "umount2", "unlink",
    "unlinkat", "unshare", "userfaultfd", "utimensat", "utimes",
]

# asm-generic legacy stubs at 1024+: present in the aarch64 table, ENOSYS at
# runtime. The 32-bit compat tables implement them for real.
AARCH64_LEGACY = [
    "open", "chmod", "chown", "lchown", "mknod", "utimes", "futimesat",
    "rmdir", "unlink", "rename",
]


def syscall_table(arch):
    names = list(MODERN_SYSCALLS)
    if arch == "aarch64":
        names = [name for name in names if name not in AARCH64_LEGACY]
    lines = ["Using %s lookup table" % arch]
    for number, name in enumerate(names):
        lines.append("%d\t%s" % (number, name))
    if arch == "aarch64":
        for offset, name in enumerate(AARCH64_LEGACY):
            lines.append("%d\t%s" % (1024 + offset, name))
    return "\n".join(lines) + "\n"


AUDITCTL_STUB = """#!/bin/sh
echo "$*" >> "{log}"
case "$1" in
  -s)
    printf 'enabled {enabled}\\nfailure 1\\npid 4242\\nrate_limit 0\\n'
    printf 'backlog_limit 8192\\nlost 0\\nbacklog 0\\n'
    ;;
  -v)
    echo "auditctl version 3.0"
    ;;
  --version)
    # Kylin's audit 3.0 rejects --version; the tool must fall back to -v.
    echo "Option --version is invalid" >&2
    exit 1
    ;;
  *)
    exit 1
    ;;
esac
"""

AUSYSCALL_STUB = """#!/bin/sh
root=$(cd "$(dirname "$0")/../.." && pwd)
cat "$root/tables/$1.txt"
"""


class Host:
    """Synthetic Kylin host root for one test."""

    def __init__(self, root, arch="x86_64", distro_id="kylin", version_id="V10",
                 cmdline="BOOT_IMAGE=/vmlinuz audit=1", uid_min=1000,
                 enabled="1", write_tools=True,
                 kernel="4.19.90-89.11.v2401.ky10"):
        self.root = Path(root)
        self.arch = arch
        self.write("etc/os-release",
                   'ID=%s\nVERSION_ID="%s"\nPRETTY_NAME="Kylin Linux Advanced Server V10 SP2"\n'
                   % (distro_id, version_id))
        self.write("proc/cmdline", cmdline + "\n")
        self.write("proc/sys/kernel/osrelease", "%s.%s\n" % (kernel, arch))
        self.write("etc/hostname", "kylin-fixture-01\n")
        self.write("etc/login.defs", "UID_MIN %d\nUID_MAX 60000\n" % uid_min)
        for table_arch in ("x86_64", "i386", "aarch64", "arm"):
            self.write("tables/%s.txt" % table_arch, syscall_table(table_arch))
        if write_tools:
            self.executable("sbin/auditctl",
                            AUDITCTL_STUB.format(log=self.root / "auditctl-calls.log",
                                                 enabled=enabled))
            self.executable("usr/sbin/ausyscall", AUSYSCALL_STUB)

    def path(self, relative):
        return self.root / relative.lstrip("/")

    def write(self, relative, content):
        target = self.path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def executable(self, relative, content):
        target = self.write(relative, content)
        target.chmod(0o755)
        return target

    def mkdirs(self, relative):
        target = self.path(relative)
        if target.exists():
            return
        target.mkdir(parents=True)

    def auditctl_calls(self):
        log = self.root / "auditctl-calls.log"
        if not log.exists():
            return []
        return [line.strip() for line in log.read_text().splitlines() if line.strip()]


def rule_tokens(path):
    """Directive token lists from a generated rules file."""
    result = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        result.append(stripped.split())
    return result


def syscalls_by_arch(tokens_list):
    by_arch = {}
    for tokens in tokens_list:
        arch = None
        for index, token in enumerate(tokens[:-1]):
            if token == "-F" and tokens[index + 1].startswith("arch="):
                arch = tokens[index + 1][5:]
        for index, token in enumerate(tokens[:-1]):
            if token == "-S":
                by_arch.setdefault(arch, set()).add(tokens[index + 1])
    return by_arch


def baseline_paths():
    """Every path the real baseline refers to, so a fixture host can hold them."""
    pattern = re.compile(r"(?:-w\s+|(?:dir|exe|path)=)(/[^\s]+)")
    found = set()
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        found.update(pattern.findall(stripped))
    return found


CORE_SOURCE = """# fixture policy
-D
-b 8192
-f 1
-i
-w /etc/audit/ -p wa -k auditconfig
-w /etc/filebeat/ -p wa -k filebeat
-a always,exit -F arch=b64 -S open -S openat -S openat2 -S open_by_handle_at -F dir=/etc -F success=0 -F auid>=1000 -F auid!=unset -k unauthedfileaccess
-a always,exit -F arch=b32 -S open -S openat -S openat2 -S open_by_handle_at -F dir=/etc -F success=0 -F auid>=1000 -F auid!=unset -k unauthedfileaccess
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S execve -S execveat -F auid!=unset -k process_creation_user
-a always,exit -F arch=b32 -S execve -S execveat -F auid!=unset -k process_creation_user
-a always,exit -F arch=b64 -S execve -S execveat -F exe=/usr/bin/bash -k process_creation_bash
-a always,exit -F arch=b32 -S execve -S execveat -F exe=/usr/bin/bash -k process_creation_bash
-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -S renameat2 -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -S renameat2 -F auid>=1000 -F auid!=unset -k delete
"""


class PrepareKylinRulesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def make_host(self, **kwargs):
        root = self.base / "sysroot"
        root.mkdir(parents=True, exist_ok=True)
        host = Host(root, **kwargs)
        host.mkdirs("/etc/audit")
        host.mkdirs("/usr/bin")
        host.write("/usr/bin/bash", "")
        return host

    def make_source(self, text, name="rules"):
        path = self.base / ("%s.rules" % name)
        path.write_text(text, encoding="utf-8")
        return path

    def run_tool(self, host, source, output_dir, arch=None, extra=None):
        command = [
            sys.executable, str(TOOL),
            "--source", str(source),
            "--output-dir", str(output_dir),
            "--sysroot", str(host.root),
        ]
        if arch:
            command += ["--arch", arch]
        if extra:
            command += list(extra)
        return subprocess.run(command, capture_output=True, text=True, timeout=120)

    def generate(self, arch="x86_64", source_text=CORE_SOURCE, **host_kwargs):
        host = self.make_host(arch=arch, **host_kwargs)
        source = self.make_source(source_text)
        output = self.base / "out"
        result = self.run_tool(host, source, output, arch=arch)
        return host, output, result

    # -- safe preflight ---------------------------------------------------- #

    def test_audit_zero_exits_nonzero_without_artifacts(self):
        host, output, result = self.generate(
            cmdline="BOOT_IMAGE=/vmlinuz root=/dev/sda1 audit=0")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("audit=0", result.stderr)
        self.assertIn("not missing kernel audit support", result.stderr)
        self.assertFalse((output / "99-dayu.rules").exists())
        self.assertFalse((output / "coverage.json").exists())

    def test_audit_disabled_at_runtime_exits_nonzero(self):
        host, output, result = self.generate(enabled="0")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("enabled", result.stderr)

    def test_unsupported_distribution_is_refused(self):
        host, output, result = self.generate(distro_id="ubuntu")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("unsupported distribution", result.stderr)

    def test_kylin_version_forms_are_accepted(self):
        for version_id in ("V10", "10", "10.1"):
            with self.subTest(version_id=version_id):
                root = self.base / ("sysroot-ver-" + version_id)
                root.mkdir(parents=True, exist_ok=True)
                host = Host(root, arch="x86_64", version_id=version_id)
                host.mkdirs("/etc/audit")
                host.mkdirs("/usr/bin")
                host.write("/usr/bin/bash", "")
                source = self.make_source(CORE_SOURCE)
                output = self.base / ("out-ver-" + version_id)
                result = self.run_tool(host, source, output, arch="x86_64")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_unsupported_kylin_version_is_refused(self):
        host, output, result = self.generate(version_id="9")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("unsupported Kylin version", result.stderr)

    def test_existing_output_is_not_overwritten(self):
        host = self.make_host(arch="x86_64")
        source = self.make_source(CORE_SOURCE)
        output = self.base / "out"
        output.mkdir()
        existing = output / "coverage.json"
        existing.write_text('{"keep": true}\n')
        result = self.run_tool(host, source, output, arch="x86_64")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(existing.read_text(), '{"keep": true}\n')
        self.assertFalse((output / "99-dayu.rules").exists())

    def test_output_path_that_is_a_file_is_refused(self):
        host = self.make_host(arch="x86_64")
        source = self.make_source(CORE_SOURCE)
        bogus = self.base / "not-a-dir"
        bogus.write_text("x")
        result = self.run_tool(host, source, bogus, arch="x86_64")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("already exists", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(bogus.read_text(), "x")

    def test_output_path_symlink_is_not_followed(self):
        host = self.make_host(arch="x86_64")
        source = self.make_source(CORE_SOURCE)
        real = self.base / "elsewhere"
        real.mkdir()
        sentinel = real / "sentinel"
        sentinel.write_text("DO NOT OVERWRITE")
        output = self.base / "out"
        output.symlink_to(real, target_is_directory=True)
        result = self.run_tool(host, source, output, arch="x86_64")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(sentinel.read_text(), "DO NOT OVERWRITE")
        self.assertEqual(sorted(item.name for item in real.iterdir()), ["sentinel"])

    def test_platform_without_atomic_rename_publishes_nothing(self):
        module = load_generator()
        case = self.base / "no-atomic"
        case.mkdir()
        host = Host(case / "host")
        host.mkdirs("/etc/audit")
        host.mkdirs("/usr/bin")
        host.write("/usr/bin/bash", "")
        source = case / "source.rules"
        source.write_text(CORE_SOURCE)
        output = case / "out"
        argv = ["--source", str(source), "--output-dir", str(output),
                "--sysroot", str(host.root), "--arch", "x86_64"]
        with mock.patch.object(module, "rename_no_replace", return_value=False), \
                contextlib.redirect_stdout(io.StringIO()):
            code = module.main(argv)
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())
        self.assertEqual([item.name for item in case.iterdir()
                          if item.name.startswith(".out.")], [])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(module.main(argv), 0)
        self.assertEqual(sorted(item.name for item in output.iterdir()),
                         ["99-dayu.rules", "coverage.json"])

    def test_directory_created_during_generation_is_not_replaced(self):
        host = self.make_host(arch="x86_64")
        source = self.make_source(CORE_SOURCE)
        output = self.base / "out"
        module = load_generator()
        real_load = module.load_tables
        original_inode = {}

        def load_and_create(*args, **kwargs):
            tables = real_load(*args, **kwargs)
            output.mkdir()
            original_inode["value"] = output.stat().st_ino
            return tables

        with mock.patch.object(module, "load_tables", load_and_create), \
                contextlib.redirect_stdout(io.StringIO()):
            code = module.main(["--source", str(source), "--output-dir", str(output),
                                "--sysroot", str(host.root), "--arch", "x86_64"])
        self.assertEqual(code, 3)
        self.assertTrue(output.is_dir())
        self.assertEqual(output.stat().st_ino, original_inode["value"])
        self.assertEqual(list(output.iterdir()), [])

    def test_control_items_are_never_executed(self):
        host, output, result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = host.auditctl_calls()
        self.assertTrue(calls)
        self.assertEqual(set(calls), {"-s", "-v"})
        self.assertIn(["-D"], rule_tokens(output / "99-dayu.rules"))

    # -- syscall adaptation ------------------------------------------------- #

    def test_x86_64_drops_openat2_but_keeps_access_rules(self):
        host, output, result = self.generate(arch="x86_64")
        self.assertEqual(result.returncode, 0, result.stderr)
        tokens = rule_tokens(output / "99-dayu.rules")
        calls = syscalls_by_arch(tokens)
        self.assertNotIn("openat2", calls["b64"])
        self.assertNotIn("openat2", calls["b32"])
        self.assertTrue({"open", "openat", "open_by_handle_at"} <= calls["b64"])
        unauthed = [tokens for tokens in tokens if "unauthedfileaccess" in tokens]
        self.assertEqual(len(unauthed), 2)
        coverage = json.loads((output / "coverage.json").read_text())
        adapted = [
            record for record in coverage["rules"]
            if record["status"] == "adapted" and record["key"] == "unauthedfileaccess"
        ]
        self.assertEqual(len(adapted), 2)
        self.assertIn("openat2", " ".join(adapted[0]["dropped_syscalls"]))

    def test_aarch64_drops_unimplemented_legacy_names_only_on_native_abi(self):
        host, output, result = self.generate(arch="aarch64")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = syscalls_by_arch(rule_tokens(output / "99-dayu.rules"))
        native = calls["b64"]
        compat = calls["b32"]
        for name in ("open", "chmod", "unlink", "rename", "rmdir"):
            self.assertNotIn(name, native)
            self.assertIn(name, compat)
        self.assertTrue({"openat", "fchmod", "fchmodat", "unlinkat", "renameat2"} <= native)
        self.assertTrue({"openat", "unlinkat"} <= compat)
        coverage = json.loads((output / "coverage.json").read_text())
        self.assertEqual(coverage["abi_tables"]["b64"]["libaudit_table"], "aarch64")
        self.assertEqual(coverage["abi_tables"]["b32"]["libaudit_table"], "arm")
        self.assertIn("open", coverage["abi_tables"]["b64"]["unimplemented_names_dropped"])
        legacy_reasons = [
            record["reason"] for record in coverage["rules"]
            if record["status"] == "adapted"
        ]
        self.assertTrue(any("kernel ENOSYS on aarch64" in reason for reason in legacy_reasons))

    def baseline_host(self, arch, suffix="", **kwargs):
        root = self.base / ("sysroot-" + arch + suffix)
        root.mkdir(parents=True, exist_ok=True)
        host = Host(root, arch=arch, **kwargs)
        targets = baseline_paths()
        self.assertGreater(len(targets), 40)
        for target in targets:
            host.mkdirs(target)
        return host

    def test_real_baseline_keeps_every_key_on_both_architectures(self):
        for arch in ("x86_64", "aarch64"):
            with self.subTest(arch=arch):
                host = self.baseline_host(arch)
                output = self.base / ("out-" + arch)
                result = self.run_tool(host, BASELINE, output, arch=arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                coverage = json.loads((output / "coverage.json").read_text())
                self.assertEqual(coverage["architecture"], arch)
                self.assertEqual(coverage["keys_without_rules"], [])
                for key in ("process_creation_user", "process_creation_bash",
                            "unauthedfileaccess", "perm_mod", "delete"):
                    self.assertGreater(coverage["critical_keys"][key], 0, key)
                tokens = rule_tokens(output / "99-dayu.rules")
                self.assertNotIn("openat2", syscalls_by_arch(tokens)["b64"])
                self.assertNotIn(["−i"], tokens)
                self.assertNotIn(["-i"], tokens)
                self.assertGreater(len(tokens), 80)

    def test_comma_separated_syscall_list_is_expanded(self):
        source = self.make_source(
            "-a always,exit -F arch=b64 -S mount,umount2 -F auid!=unset"
            " -k mount_list\n" + CORE_SOURCE)
        host = self.make_host(arch="x86_64")
        output = self.base / "out-comma"
        result = self.run_tool(host, source, output, arch="x86_64")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [line for line in (output / "99-dayu.rules").read_text().splitlines()
                 if "-k mount_list" in line]
        self.assertEqual(len(lines), 1)
        self.assertIn("-S mount,umount2", lines[0])
        coverage = json.loads((output / "coverage.json").read_text())
        record = [item for item in coverage["rules"] if item["key"] == "mount_list"][0]
        self.assertEqual(record["status"], "kept")

    def test_comma_list_keeps_the_supported_names(self):
        source = self.make_source(
            "-a always,exit -F arch=b64 -S openat,openat2 -F dir=/etc -F success=0"
            " -F auid>=1000 -F auid!=unset -k unauthedfileaccess\n" + CORE_SOURCE)
        host = self.make_host(arch="x86_64")
        output = self.base / "out-comma-partial"
        result = self.run_tool(host, source, output, arch="x86_64")
        self.assertEqual(result.returncode, 0, result.stderr)
        coverage = json.loads((output / "coverage.json").read_text())
        record = [item for item in coverage["rules"] if item["source_line"] == 1][0]
        self.assertEqual(record["status"], "adapted")
        self.assertEqual(record["dropped_syscalls"], ["openat2"])
        generated = (output / "99-dayu.rules").read_text().splitlines()
        line = generated[record["generated_lines"][0] - 1]
        self.assertIn("-S openat", line)
        self.assertNotIn("openat2", line)
        self.assertEqual([item for item in coverage["critical_keys"]],
                         ["process_creation_user", "process_creation_bash",
                          "unauthedfileaccess", "perm_mod", "delete"])

    def test_table_listing_openat2_does_not_keep_it(self):
        for arch in ("x86_64", "aarch64"):
            with self.subTest(arch=arch):
                host = self.make_host(arch=arch)
                for abi in ("x86_64", "i386", "aarch64", "arm"):
                    host.write("tables/%s.txt" % abi,
                               syscall_table(abi) + "437\topenat2\n")
                output = self.base / ("out-openat2-" + arch)
                result = self.run_tool(host, self.make_source(CORE_SOURCE), output, arch=arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = syscalls_by_arch(rule_tokens(output / "99-dayu.rules"))
                self.assertNotIn("openat2", calls["b64"])
                self.assertNotIn("openat2", calls["b32"])
                self.assertTrue({"openat", "open_by_handle_at"} <= calls["b64"])

    def test_compat_table_is_queried_separately(self):
        host = self.make_host(arch="x86_64")
        host.write("tables/i386.txt", "\n".join(
            line for line in syscall_table("i386").splitlines()
            if not line.endswith("\tkexec_file_load")) + "\n")
        source = self.make_source(
            "-a always,exit -F arch=b64 -S kexec_file_load -k KEXEC\n"
            "-a always,exit -F arch=b32 -S kexec_file_load -k KEXEC\n"
            + CORE_SOURCE)
        output = self.base / "out-compat"
        result = self.run_tool(host, source, output, arch="x86_64")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = syscalls_by_arch(rule_tokens(output / "99-dayu.rules"))
        self.assertIn("kexec_file_load", calls["b64"])
        self.assertNotIn("kexec_file_load", calls["b32"])
        coverage = json.loads((output / "coverage.json").read_text())
        skipped = [record for record in coverage["rules"] if record["status"] == "skipped"]
        self.assertTrue(any("kexec_file_load" in record["reason"] for record in skipped))

    def test_unsupported_kernel_series_is_refused(self):
        host, output, result = self.generate(kernel="6.6.1-kylin")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("unsupported kernel", result.stderr)
        self.assertFalse((output / "99-dayu.rules").exists())

    def test_critical_syscall_absent_from_table_fails(self):
        host = self.make_host(arch="x86_64")
        host.write("tables/x86_64.txt", "\n".join(
            line for line in syscall_table("x86_64").splitlines()
            if not line.endswith("\texecve")) + "\n")
        output = self.base / "out-missing-execve"
        result = self.run_tool(host, self.make_source(CORE_SOURCE), output, arch="x86_64")
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn("critical syscall 'execve'", result.stderr)
        self.assertIn("process_creation_user", result.stderr)
        self.assertFalse((output / "99-dayu.rules").exists())

    # -- identity threshold, paths, report -------------------------------- #

    def test_uid_min_replaces_only_the_identity_threshold(self):
        host, output, result = self.generate(uid_min=500)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = (output / "99-dayu.rules").read_text()
        self.assertIn("auid>=500", text)
        self.assertNotIn("auid>=1000", text)
        coverage = json.loads((output / "coverage.json").read_text())
        self.assertEqual(coverage["uid_min"], 500)
        self.assertTrue(any(
            "auid>=1000 replaced" in record["reason"] for record in coverage["rules"]))

    def test_uid_min_applies_to_rules_without_syscalls(self):
        source = self.make_source(
            "-a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=unset"
            " -C auid!=obj_uid -k power_abuse\n" + CORE_SOURCE)
        host = self.make_host(arch="x86_64", uid_min=500)
        host.mkdirs("/home")
        output = self.base / "out-power"
        result = self.run_tool(host, source, output, arch="x86_64")
        self.assertEqual(result.returncode, 0, result.stderr)
        power = [line for line in (output / "99-dayu.rules").read_text().splitlines()
                 if "-k power_abuse" in line]
        self.assertEqual(len(power), 1)
        self.assertIn("auid>=500", power[0])
        self.assertNotIn("auid>=1000", power[0])
        coverage = json.loads((output / "coverage.json").read_text())
        record = [item for item in coverage["rules"] if item["key"] == "power_abuse"][0]
        self.assertEqual(record["status"], "adapted")
        self.assertIn("auid>=500", record["reason"])

    def test_uid_min_self_check_ignores_comments(self):
        host, output, result = self.generate(
            uid_min=500, source_text=CORE_SOURCE + "# historical auid>=1000 note\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("auid>=500", (output / "99-dayu.rules").read_text())

    def test_uid_only_change_is_reported_as_adapted(self):
        host, output, result = self.generate(uid_min=500)
        self.assertEqual(result.returncode, 0, result.stderr)
        coverage = json.loads((output / "coverage.json").read_text())
        perm_mod = [record for record in coverage["rules"] if record["key"] == "perm_mod"]
        self.assertTrue(perm_mod)
        for record in perm_mod:
            self.assertEqual(record["status"], "adapted")
            self.assertIn("auid>=500", record["reason"])

    def test_real_baseline_with_non_default_uid_min(self):
        host = self.baseline_host("x86_64", "-uid500", uid_min=500)
        output = self.base / "out-uid500"
        result = self.run_tool(host, BASELINE, output, arch="x86_64")
        self.assertEqual(result.returncode, 0, result.stderr)
        directives = [line for line in (output / "99-dayu.rules").read_text().splitlines()
                      if not line.lstrip().startswith("#")]
        self.assertFalse(any("auid>=1000" in line.split() for line in directives))
        self.assertTrue(any("auid>=500" in line.split() for line in directives))
        coverage = json.loads((output / "coverage.json").read_text())
        self.assertEqual(coverage["uid_min"], 500)
        power = [record for record in coverage["rules"] if record["key"] == "power_abuse"]
        self.assertEqual(power[0]["status"], "adapted")

    def test_missing_path_is_skipped_reported_and_keeps_other_keys(self):
        host, output, result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        coverage = json.loads((output / "coverage.json").read_text())
        self.assertIn("filebeat", coverage["keys_without_rules"])
        skipped = [record for record in coverage["rules"] if record["status"] == "skipped"]
        self.assertTrue(any("/etc/filebeat/" in record["reason"] for record in skipped))
        self.assertNotIn("filebeat", (output / "99-dayu.rules").read_text())
        self.assertEqual(coverage["key_summary"]["auditconfig"]["generated_rules"], 1)

    def test_critical_key_losing_all_rules_fails_without_output(self):
        source_text = CORE_SOURCE.replace(
            "-a always,exit -F arch=b64 -S open -S openat -S openat2 -S open_by_handle_at"
            " -F dir=/etc -F success=0 -F auid>=1000 -F auid!=unset -k unauthedfileaccess\n"
            "-a always,exit -F arch=b32 -S open -S openat -S openat2 -S open_by_handle_at"
            " -F dir=/etc -F success=0 -F auid>=1000 -F auid!=unset -k unauthedfileaccess",
            "-a always,exit -F arch=b64 -S openat2 -F dir=/etc -F success=0"
            " -F auid>=1000 -F auid!=unset -k unauthedfileaccess\n"
            "-a always,exit -F arch=b32 -S openat2 -F dir=/etc -F success=0"
            " -F auid>=1000 -F auid!=unset -k unauthedfileaccess",
        )
        self.assertEqual(source_text.count("unauthedfileaccess"), 2)
        host, output, result = self.generate(source_text=source_text)
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn("unauthedfileaccess", result.stderr)
        self.assertFalse((output / "99-dayu.rules").exists())
        self.assertFalse((output / "coverage.json").exists())

    def test_failure_after_first_artifact_leaves_nothing(self):
        module = load_generator()
        case = self.base / "midway"
        case.mkdir()
        host = Host(case / "host")
        host.mkdirs("/etc/audit")
        host.mkdirs("/usr/bin")
        host.write("/usr/bin/bash", "")
        source = case / "source.rules"
        source.write_text(CORE_SOURCE)
        output = case / "out"
        real_write = Path.write_text

        def fail_on_coverage(self_path, *args, **kwargs):
            if self_path.name == "coverage.json":
                raise OSError(errno.ENOSPC, "injected after the rules file")
            return real_write(self_path, *args, **kwargs)

        argv = ["--source", str(source), "--output-dir", str(output),
                "--sysroot", str(host.root), "--arch", "x86_64"]
        with mock.patch.object(Path, "write_text", fail_on_coverage), \
                contextlib.redirect_stdout(io.StringIO()):
            code = module.main(argv)
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())
        self.assertEqual([item.name for item in case.iterdir()
                          if item.name.startswith(".out.")], [])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(module.main(argv), 0)
        self.assertEqual(sorted(item.name for item in output.iterdir()),
                         ["99-dayu.rules", "coverage.json"])

    def test_coverage_report_is_traceable(self):
        host, output, result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        coverage = json.loads((output / "coverage.json").read_text())
        for field in ("host", "architecture", "kernel", "audit_version",
                      "source_sha256", "generated_sha256", "rules"):
            self.assertIn(field, coverage)
        rules_path = output / "99-dayu.rules"
        self.assertEqual(
            coverage["generated_sha256"],
            hashlib.sha256(rules_path.read_bytes()).hexdigest())
        self.assertEqual(
            coverage["source_sha256"],
            hashlib.sha256(CORE_SOURCE.encode("utf-8")).hexdigest())
        generated_lines = rules_path.read_text().splitlines()
        self.assertEqual(coverage["host"], "kylin-fixture-01")
        self.assertEqual(coverage["audit_version"], "auditctl version 3.0")
        self.assertEqual(coverage["architecture"], "x86_64")
        for record in coverage["rules"]:
            for field in ("source_line", "key", "status", "reason", "generated_lines"):
                self.assertIn(field, record)
            for line_number in record["generated_lines"]:
                line = generated_lines[line_number - 1]
                self.assertFalse(line.lstrip().startswith("#"))
                if record["key"]:
                    self.assertIn(record["key"], line)
        self.assertGreater(coverage["counts"]["kept"], 0)
        self.assertGreater(coverage["counts"]["adapted"], 0)
        self.assertEqual(coverage["counts"]["skipped"], 1)

    def test_ignore_errors_flag_is_removed_from_output(self):
        host, output, result = self.generate()
        self.assertEqual(result.returncode, 0, result.stderr)
        directives = [" ".join(tokens) for tokens in rule_tokens(output / "99-dayu.rules")]
        self.assertNotIn("-i", directives)
        coverage = json.loads((output / "coverage.json").read_text())
        ignored = [record for record in coverage["rules"]
                   if record["status"] == "adapted" and record["key"] is None
                   and "-i removed" in record["reason"]]
        self.assertEqual(len(ignored), 1)


class LiveHostGuardTest(unittest.TestCase):
    def test_arch_override_is_rejected_without_fixture_sysroot(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(TOOL), "--source", str(BASELINE),
                 "--output-dir", str(Path(tmp) / "out"), "--arch", "x86_64"],
                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("--arch", result.stderr)


class PublicationTest(unittest.TestCase):
    """The rules + coverage pair must appear all at once or not at all."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.module = load_generator()

    def prepare(self, name, extra_rule=""):
        case = self.base / name
        case.mkdir()
        host = Host(case / "host")
        host.mkdirs("/etc/audit")
        host.mkdirs("/usr/bin")
        host.write("/usr/bin/bash", "")
        source = case / ("src-%s.rules" % name)
        source.write_text(CORE_SOURCE + extra_rule)
        return case, host, source

    def argv(self, host, source, output):
        return ["--source", str(source), "--output-dir", str(output),
                "--sysroot", str(host.root), "--arch", "x86_64"]

    def test_failure_before_publish_leaves_nothing_and_allows_retry(self):
        case, host, source = self.prepare("fail")
        output = case / "out"
        argv = self.argv(host, source, output)
        with mock.patch.object(self.module.tempfile, "mkdtemp",
                               side_effect=OSError(errno.ENOSPC, "injected")):
            with contextlib.redirect_stdout(io.StringIO()):
                code = self.module.main(argv)
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())
        self.assertEqual([item.name for item in case.iterdir()
                          if item.name.startswith(".out.")], [])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.module.main(argv), 0)
        self.assertTrue((output / "99-dayu.rules").is_file())
        self.assertTrue((output / "coverage.json").is_file())

    def test_concurrent_runs_publish_one_consistent_pair(self):
        case, host, source_a = self.prepare("race", "-w /etc/audit/ -p wa -k extra_a\n")
        source_b = case / "src-b.rules"
        source_b.write_text(CORE_SOURCE + "-w /etc/audit/ -p wa -k extra_b\n")
        output = case / "out"
        barrier = threading.Barrier(2)
        real_load_tables = self.module.load_tables

        def synced_load_tables(*args, **kwargs):
            result = real_load_tables(*args, **kwargs)
            barrier.wait(timeout=30)
            return result

        codes = {}

        def run(label, source):
            # No stdout redirection here: redirect_stdout swaps a process-wide
            # object and two threads doing that would race with each other.
            codes[label] = self.module.main(self.argv(host, source, output))

        with mock.patch.object(self.module, "load_tables", synced_load_tables):
            threads = [
                threading.Thread(target=run, args=("a", source_a)),
                threading.Thread(target=run, args=("b", source_b)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(60)

        self.assertEqual(sorted(codes.values()), [0, 3])
        coverage = json.loads((output / "coverage.json").read_text())
        rules_bytes = (output / "99-dayu.rules").read_bytes()
        self.assertEqual(coverage["generated_sha256"],
                         hashlib.sha256(rules_bytes).hexdigest())
        self.assertEqual(sorted(item.name for item in output.iterdir()),
                         ["99-dayu.rules", "coverage.json"])
        # Exactly one source may be represented, and rules/coverage must agree.
        # Match the full key names: a single letter also occurs in words such as
        # "always", which would always pick the first candidate.
        for marker, source in (("-k extra_a", source_a), ("-k extra_b", source_b)):
            if marker.encode() in rules_bytes:
                self.assertEqual(coverage["source_file"], str(source))
                self.assertEqual(
                    coverage["source_sha256"],
                    hashlib.sha256(source.read_bytes()).hexdigest())
                break
        else:
            self.fail("no source marker found in the published rules")


if __name__ == "__main__":
    unittest.main()
