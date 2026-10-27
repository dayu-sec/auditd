#!/usr/bin/env python3
"""Generate Kylin V10 (4.19 series, x86_64/aarch64) auditd rules + coverage report.

Read-only preflight, then a per-line adaptation of `audit.rules`:

* only a Kylin V10 4.19 host with auditing enabled and a known UID_MIN is
  accepted; anything else fails without producing a deployable artifact;
* syscall names are resolved against the *host's* libaudit ABI tables
  (`ausyscall <arch> --dump`), never against a hard-coded syscall number list;
* names the kernel answers with ENOSYS (openat2 on 4.19, aarch64 legacy stubs)
  are dropped even when libaudit lists them, and a critical syscall that cannot
  be confirmed in the table fails the run instead of being trimmed;
* missing `-w` / `dir=` / `exe=` / `path=` targets are skipped and reported;
* `auid>=1000` is rewritten to the host UID_MIN taken from /etc/login.defs;
* `-i` is removed so a later load fails loudly instead of silently dropping
  rules; control items (`-D`, `-b`, ...) are copied but never executed here.

Usage (on the Kylin host, repository checkout):

    python3 scripts/prepare-kylin-rules.py --source audit.rules --output-dir /var/tmp/dayu-kylin

Outputs `99-dayu.rules` and `coverage.json` in the output directory. The tool
never loads rules, never edits boot parameters and never restarts anything.

Exit codes:
  0  rules + coverage generated
  2  host/preflight gate failed (unsupported distro/version/kernel/arch, audit
     disabled, no tooling, unknown UID_MIN)
  3  output directory already holds artifacts (refusing to overwrite)
  4  coverage gate failed (a critical key lost all of its rules, or a critical
     syscall cannot be confirmed in the host ABI table)

`--sysroot`/`--arch` exist for the repository test-suite fixtures; both are
rejected on a live host (`--sysroot` other than `/` is only for fixtures and
`--arch` is only accepted together with such a sysroot).
"""

import argparse
import ctypes
import errno
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

EXIT_ENV = 2
EXIT_OUTPUT_EXISTS = 3
EXIT_ADAPTATION = 4

RULES_NAME = "99-dayu.rules"
COVERAGE_NAME = "coverage.json"

# ABI tables required per architecture, as named by `ausyscall <arch> --dump`.
ARCH_ABI_TABLES = {
    "x86_64": {"b64": "x86_64", "b32": "i386"},
    "aarch64": {"b64": "aarch64", "b32": "arm"},
}

# Names the target kernel cannot execute, no matter what the host libaudit
# table lists. A name in the table only proves the userspace mapping exists;
# the kernel still answers these with ENOSYS, so a rule filtering on them can
# never fire.
#
# "*" applies to every ABI: openat2 landed in 5.6 and returns ENOSYS on the
# Kylin V10 4.19 series (probed on both architectures). The aarch64 entry
# lists the asm-generic legacy stubs at 1024+, which exist only for the
# 32-bit compat ABI (arm) and must stay there.
KERNEL_UNIMPLEMENTED = {
    "*": frozenset(("openat2",)),
    "aarch64": frozenset(
        (
            "open",
            "chmod",
            "chown",
            "lchown",
            "mknod",
            "utimes",
            "futimesat",
            "rmdir",
            "unlink",
            "rename",
        )
    ),
}

# Kernel series this generator is validated against. Anything else is refused
# instead of silently reusing facts measured on another kernel.
SUPPORTED_KERNEL_SERIES = ("4.19.",)


def unimplemented_for(table_arch):
    return KERNEL_UNIMPLEMENTED["*"] | KERNEL_UNIMPLEMENTED.get(table_arch, frozenset())

# Keys that must survive adaptation. A category the policy covers cannot be
# reported as covered when every one of its rules was dropped.
CRITICAL_KEYS = (
    "process_creation_user",
    "process_creation_bash",
    "unauthedfileaccess",
    "perm_mod",
    "delete",
)

SYSCALL_DUMP_RE = re.compile(r"^(\d+)[\s:;\t]+([A-Za-z_][A-Za-z0-9_]*)$")
AUID_THRESHOLD_TOKEN = "auid>=1000"


class Failure(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------- #
# Host facts (read-only)
# --------------------------------------------------------------------------- #


def read_text(path, default=None):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return default


def parse_os_release(text):
    data = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def resolve_tool(sysroot, name):
    for candidate in (
        sysroot / "usr" / "sbin" / name,
        sysroot / "sbin" / name,
        sysroot / "usr" / "bin" / name,
        sysroot / "bin" / name,
    ):
        if candidate.is_file() and os.access(str(candidate), os.X_OK):
            return str(candidate)
    return shutil.which(name)


def run_command(cmd):
    try:
        return subprocess.run(
            [str(part) for part in cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=60,
        )
    except OSError as exc:
        raise Failure(EXIT_ENV, "cannot execute %s: %s" % (cmd[0], exc))


def detect_audit_version(auditctl):
    """audit 3.0 on Kylin rejects `--version`; `-v` works on every release."""
    for flag in ("-v", "--version"):
        proc = run_command([auditctl, flag])
        text = ((proc.stdout or "") + (proc.stderr or "")).strip()
        match = re.search(r"version\s+([0-9][0-9A-Za-z.+~\-]*)", text, re.IGNORECASE)
        if match:
            return "auditctl version %s" % match.group(1)
    return "unknown"


def detect_arch(args):
    if args.arch:
        return args.arch
    machine = platform.machine().lower()
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    return machine


def gather_host_facts(args):
    sysroot = Path(args.sysroot).resolve()
    if args.arch and sysroot == Path("/"):
        raise Failure(
            EXIT_ENV,
            "--arch is only accepted next to a fixture --sysroot; on a real "
            "host the architecture is detected, not chosen",
        )
    if sysroot == Path("/") and platform.system() != "Linux":
        raise Failure(
            EXIT_ENV,
            "this generator must run on the target Kylin host (got %s); "
            "use a fixture --sysroot only from the test-suite"
            % platform.system(),
        )

    os_release_text = read_text(sysroot / "etc" / "os-release")
    if os_release_text is None:
        raise Failure(EXIT_ENV, "cannot read %s" % (sysroot / "etc" / "os-release"))
    os_release = parse_os_release(os_release_text)
    distro_id = os_release.get("ID", "").lower()
    version_id = os_release.get("VERSION_ID", "")
    if distro_id != "kylin":
        raise Failure(
            EXIT_ENV,
            "unsupported distribution ID=%r (%s); this generator only supports "
            "Kylin V10 (ID=kylin, VERSION_ID 10.x)"
            % (distro_id, os_release.get("PRETTY_NAME", "unknown")),
        )
    # Kylin reports VERSION_ID="V10" (and some builds "10"); both are V10.
    normalized_version = version_id.strip()
    if normalized_version[:1] in ("v", "V"):
        normalized_version = normalized_version[1:]
    major_version = normalized_version.split(".")[0]
    if major_version != "10":
        raise Failure(
            EXIT_ENV,
            "unsupported Kylin version %r (%s); only the V10 4.19 series is "
            "covered, do not claim wider Kylin compatibility"
            % (version_id, os_release.get("PRETTY_NAME", "unknown")),
        )

    arch = detect_arch(args)
    if arch not in ARCH_ABI_TABLES:
        raise Failure(
            EXIT_ENV,
            "unsupported architecture %r; supported: %s"
            % (arch, ", ".join(sorted(ARCH_ABI_TABLES))),
        )

    kernel = read_text(sysroot / "proc" / "sys" / "kernel" / "osrelease")
    kernel = kernel.strip() if kernel else platform.release()
    if not kernel.startswith(SUPPORTED_KERNEL_SERIES):
        raise Failure(
            EXIT_ENV,
            "unsupported kernel %r: only the Kylin V10 %s series is covered, "
            "where the openat2/legacy-stub behaviour was measured. Extend the "
            "generator with measured facts before adapting another kernel. "
            "Nothing was changed by this tool."
            % (kernel, " / ".join(SUPPORTED_KERNEL_SERIES)),
        )
    cmdline = (read_text(sysroot / "proc" / "cmdline") or "").strip()
    hostname = (read_text(sysroot / "etc" / "hostname") or "").strip()
    if not hostname:
        hostname = socket.gethostname()

    boot_tokens = cmdline.split()
    if "audit=0" in boot_tokens:
        raise Failure(
            EXIT_ENV,
            "kernel auditing is disabled by the boot parameter audit=0 "
            "(/proc/cmdline); rules cannot be loaded until the boot "
            "configuration sets audit=1 and the host is rebooted in an agreed "
            "maintenance window. This is a boot/configuration problem, not "
            "missing kernel audit support (CONFIG_AUDIT=y, CONFIG_AUDITSYSCALL=y). "
            "Nothing was changed by this tool.",
        )
    audit_boot_parameter = "audit=1" if "audit=1" in boot_tokens else "not set (kernel default enabled)"

    auditctl = resolve_tool(sysroot, "auditctl")
    if not auditctl:
        raise Failure(
            EXIT_ENV,
            "auditctl not found; install the distribution audit package on the "
            "target host before generating rules",
        )
    status_proc = run_command([auditctl, "-s"])
    if status_proc.returncode != 0:
        raise Failure(
            EXIT_ENV,
            "`auditctl -s` failed (exit %d): %s -- a failing auditctl usually "
            "means the audit subsystem is switched off (audit=0 in the boot "
            "parameters) or the kernel has no netlink audit socket enabled; "
            "check /proc/cmdline and CONFIG_AUDIT/CONFIG_AUDITSYSCALL before "
            "concluding that audit support is missing. Nothing was changed by "
            "this tool."
            % (status_proc.returncode, (status_proc.stderr or status_proc.stdout).strip()),
        )
    audit_status = {}
    for line in status_proc.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            audit_status[parts[0]] = parts[1].strip()
    if audit_status.get("enabled") != "1":
        raise Failure(
            EXIT_ENV,
            "audit is not enabled at runtime (auditctl -s reports enabled=%r); "
            "fix the boot parameter (audit=1) and the auditd service in a "
            "maintenance window, then regenerate. Nothing was changed by this tool."
            % audit_status.get("enabled"),
        )

    login_defs = read_text(sysroot / "etc" / "login.defs")
    uid_min = None
    if login_defs:
        for line in login_defs.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "UID_MIN" and parts[1].isdigit():
                uid_min = int(parts[1])
                break
    if uid_min is None:
        raise Failure(
            EXIT_ENV,
            "cannot determine UID_MIN from %s; refusing to guess the identity "
            "threshold" % (sysroot / "etc" / "login.defs"),
        )

    audit_version = detect_audit_version(auditctl)

    return {
        "sysroot": sysroot,
        "arch": arch,
        "distro": os_release.get("PRETTY_NAME", distro_id),
        "distro_id": distro_id,
        "distro_version": version_id,
        "kernel": kernel,
        "kernel_cmdline": cmdline,
        "hostname": hostname,
        "audit_boot_parameter": audit_boot_parameter,
        "audit_version": audit_version,
        "audit_status": audit_status,
        "uid_min": uid_min,
        "auditctl": auditctl,
    }


# --------------------------------------------------------------------------- #
# libaudit ABI tables
# --------------------------------------------------------------------------- #


def load_syscall_table(ausyscall, table_arch):
    proc = run_command([ausyscall, table_arch, "--dump"])
    if proc.returncode != 0:
        raise Failure(
            EXIT_ENV,
            "`ausyscall %s --dump` failed (exit %d): %s; cannot confirm the "
            "ABI syscall table, refusing to trim rules blindly"
            % (table_arch, proc.returncode, (proc.stderr or proc.stdout).strip()),
        )
    table = {}
    for line in proc.stdout.splitlines():
        match = SYSCALL_DUMP_RE.match(line.strip())
        if not match:
            continue
        table.setdefault(match.group(2), int(match.group(1)))
    if not table:
        raise Failure(
            EXIT_ENV,
            "`ausyscall %s --dump` produced no parsable syscall table; "
            "libaudit on this host is unusable for rule adaptation" % table_arch,
        )
    return table


def load_tables(facts, source_tokens):
    ausyscall = resolve_tool(facts["sysroot"], "ausyscall")
    if not ausyscall:
        raise Failure(
            EXIT_ENV,
            "ausyscall not found; the libaudit ABI tables are required to adapt "
            "syscall names, install the distribution audit package",
        )
    used_abis = set()
    for tokens in source_tokens:
        if not tokens or tokens[0] != "-a":
            continue
        if "-S" in tokens:
            abi = fact_arch(tokens)
            if abi is not None:
                used_abis.add(abi)
    tables = {}
    for abi in sorted(used_abis):
        table_arch = ARCH_ABI_TABLES[facts["arch"]][abi]
        tables[abi] = load_syscall_table(ausyscall, table_arch)
    return tables


# --------------------------------------------------------------------------- #
# Rule parsing
# --------------------------------------------------------------------------- #


def fact_arch(tokens):
    arch = None
    for index, token in enumerate(tokens):
        if token == "-F" and index + 1 < len(tokens):
            value = tokens[index + 1]
            if value.startswith("arch="):
                arch = value[5:]
    return arch


def extract_key(tokens):
    for index, token in enumerate(tokens):
        if token == "-k" and index + 1 < len(tokens):
            return tokens[index + 1]
        if token == "-F" and index + 1 < len(tokens) and tokens[index + 1].startswith("key="):
            return tokens[index + 1][4:]
    return None


def path_filters(tokens):
    """Return the (-w target, -F path/dir/exe values) that must exist on disk."""
    targets = []
    for index, token in enumerate(tokens):
        if token == "-w" and index + 1 < len(tokens):
            targets.append(tokens[index + 1])
        elif token == "-F" and index + 1 < len(tokens):
            value = tokens[index + 1]
            for prefix in ("dir=", "path=", "exe="):
                if value.startswith(prefix):
                    targets.append(value[len(prefix):])
    return targets


def syscall_positions(tokens):
    """Indices of the syscall name tokens following each -S."""
    positions = []
    index = 0
    while index < len(tokens):
        if tokens[index] == "-S":
            if index + 1 >= len(tokens):
                raise Failure(EXIT_ADAPTATION, "dangling -S at end of rule: %s" % " ".join(tokens))
            positions.append(index + 1)
            index += 2
            continue
        index += 1
    return positions


def path_exists(sysroot, target):
    if not target.startswith("/"):
        return True
    return os.path.exists(str(sysroot / target.lstrip("/")))


def adapt_syscalls(tokens, table, table_arch):
    """Drop syscalls this ABI cannot run.

    `-S` accepts a comma-separated list (`-S mount,umount2`), so every argument
    is expanded and each name is checked on its own; a partly supported list
    keeps the supported names instead of losing the whole rule.

    Returns (emitted_tokens or None when nothing is left, drops) where drops is
    a list of (name, kind) and kind is "absent" (the libaudit table has no such
    name) or "unimplemented" (listed, but the kernel answers ENOSYS). The
    distinction matters: an absent critical syscall means the host cannot be
    trusted to run that policy, while an unimplemented name is a known,
    measured kernel gap.
    """
    unsupported = unimplemented_for(table_arch)
    drops = []
    replacements = {}
    for position in syscall_positions(tokens):
        names = [name for name in tokens[position].split(",") if name]
        if not names:
            raise Failure(
                EXIT_ADAPTATION,
                "empty -S argument in rule: %s" % " ".join(tokens),
            )
        kept = []
        for name in names:
            if name == "all":
                kept.append(name)
                continue
            if name.isdigit() or (name.startswith("-") and name[1:].isdigit()):
                raise Failure(
                    EXIT_ADAPTATION,
                    "numeric -S %r is ABI-specific and cannot be verified across "
                    "architectures; use syscall names" % name,
                )
            if name in unsupported:
                drops.append((name, "unimplemented"))
                continue
            if name not in table:
                drops.append((name, "absent"))
                continue
            kept.append(name)
        replacements[position] = ",".join(kept) if kept else None

    if not any(kept is not None for kept in replacements.values()):
        return None, drops

    emitted = []
    index = 0
    while index < len(tokens):
        if tokens[index] == "-S":
            kept = replacements[index + 1]
            if kept is not None:
                emitted.append("-S")
                emitted.append(kept)
            index += 2
            continue
        emitted.append(tokens[index])
        index += 1
    return emitted, drops


def substitute_uid(tokens, uid_min):
    """Replace `-F auid>=1000` with the host UID_MIN; works on every directive."""
    emitted = []
    changed = False
    index = 0
    while index < len(tokens):
        if (
            tokens[index] == "-F"
            and index + 1 < len(tokens)
            and tokens[index + 1] == AUID_THRESHOLD_TOKEN
        ):
            replacement = "auid>=%d" % uid_min
            emitted.append("-F")
            emitted.append(replacement)
            changed = changed or replacement != AUID_THRESHOLD_TOKEN
            index += 2
            continue
        emitted.append(tokens[index])
        index += 1
    return emitted, changed


# --------------------------------------------------------------------------- #
# Generation
# --------------------------------------------------------------------------- #


_RENAME_NOREPLACE = 1      # Linux renameat2 flag
_RENAME_EXCL = 0x00000004  # macOS renamex_np flag
_AT_FDCWD = -100


def rename_no_replace(source, target):
    """Atomically rename a directory, refusing to touch an existing target.

    Plain rename() replaces an empty target directory, so a path that appears
    between the existence check and publication would be silently deleted. Only
    primitives that fail instead of replacing are accepted; there is no
    degraded per-file fallback, because that would republish rules and coverage
    one at a time.

    Returns True when the rename happened, False when the platform offers no
    such primitive. Raises OSError for any other failure (EEXIST included).
    """
    source_bytes = os.fsencode(str(source))
    target_bytes = os.fsencode(str(target))
    libc = ctypes.CDLL(None, use_errno=True)

    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is not None:
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                              ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        ctypes.set_errno(0)
        if renameat2(_AT_FDCWD, source_bytes, _AT_FDCWD, target_bytes,
                     _RENAME_NOREPLACE) == 0:
            return True
        err = ctypes.get_errno()
        if err != errno.ENOSYS:
            raise OSError(err, os.strerror(err), str(target))

    renamex_np = getattr(libc, "renamex_np", None)
    if renamex_np is not None:
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        ctypes.set_errno(0)
        if renamex_np(source_bytes, target_bytes, _RENAME_EXCL) == 0:
            return True
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), str(target))

    return False


def publish_directory(staging, output_dir):
    """Publish the staging directory without ever replacing an existing path."""
    if rename_no_replace(staging, output_dir):
        return
    raise OSError(
        errno.ENOTSUP,
        "this platform offers no atomic no-replace directory rename "
        "(renameat2/renamex_np); refusing to publish a half-atomic pair",
        str(output_dir))


def header_lines(facts, source_sha, uid_min):
    return [
        "# Generated by scripts/prepare-kylin-rules.py -- do not edit by hand.",
        "# Host policy source: audit.rules (sha256=%s)" % source_sha,
        "# Target: %s, %s, kernel %s, %s" % (
            facts["distro"], facts["arch"], facts["kernel"], facts["audit_version"]),
        "# ABI tables: %s; UID_MIN=%d" % (
            ", ".join(
                "%s=%s" % (abi, ARCH_ABI_TABLES[facts["arch"]][abi])
                for abi in sorted(ARCH_ABI_TABLES[facts["arch"]])
            ),
            uid_min,
        ),
        "# `-i` was removed: unsupported syscalls and missing paths are resolved",
        "# at generation time, so a load error during deployment is a real error.",
        "# Per-rule status (kept/adapted/skipped) lives in coverage.json next to",
        "# this file. Privileged watches stay per-host: scripts/gen-privileged-rules.sh",
    ]


def generate(args):
    """
    Read-only preflight is performed before any output is written.
    """
    facts = gather_host_facts(args)

    source_path = Path(args.source)
    if not source_path.is_file():
        raise Failure(EXIT_ENV, "source rules file not found: %s" % source_path)
    source_bytes = source_path.read_bytes()
    source_sha = hashlib.sha256(source_bytes).hexdigest()
    source_lines = source_bytes.decode("utf-8").splitlines()

    tokenised = []
    for line in source_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            tokenised.append(None)
        else:
            tokenised.append(stripped.split())

    # Gates on the output location run before any expensive work and before
    # the coverage check, so a collision never produces a partial artifact.
    output_dir = Path(args.output_dir)
    rules_path = output_dir / RULES_NAME
    coverage_path = output_dir / COVERAGE_NAME
    if output_dir.exists() or output_dir.is_symlink():
        raise Failure(
            EXIT_OUTPUT_EXISTS,
            "%s already exists; this generator publishes %s and %s by renaming "
            "a complete staging directory into place, so a fresh path is "
            "required for every run. Move the old directory away instead of "
            "reusing it." % (output_dir, RULES_NAME, COVERAGE_NAME),
        )

    tables = load_tables(facts, [tokens for tokens in tokenised if tokens])

    abi_tables = ARCH_ABI_TABLES[facts["arch"]]
    out_lines = header_lines(facts, source_sha, facts["uid_min"])
    records = []
    source_keys = Counter()
    generated_keys = Counter()
    status_counts = Counter()
    dropped_by_abi = {}

    for line_number, tokens in enumerate(tokenised, start=1):
        raw = source_lines[line_number - 1]
        if tokens is None:
            out_lines.append(raw.rstrip())
            continue

        if tokens[0] == "-i":
            records.append({
                "source_line": line_number,
                "key": None,
                "status": "adapted",
                "reason": "-i removed: unsupported syscalls and missing paths are "
                          "resolved at generation time so load errors stay visible",
                "generated_lines": [],
            })
            status_counts["adapted"] += 1
            continue

        key = extract_key(tokens)
        abi = fact_arch(tokens)
        drops = []
        notes = []
        dropped = []

        if "-S" in tokens:
            if abi not in abi_tables:
                raise Failure(
                    EXIT_ADAPTATION,
                    "rule with -S but without a supported -F arch=b64|b32 "
                    "(source line %d): %s" % (line_number, raw.strip()),
                )
            table_arch = abi_tables[abi]
            table = tables.get(abi)
            if table is None:
                raise Failure(
                    EXIT_ADAPTATION,
                    "no libaudit table loaded for %s (source line %d); refusing "
                    "to keep unverified syscalls" % (table_arch, line_number),
                )
            emitted, drops = adapt_syscalls(tokens, table, table_arch)
            dropped = [name for name, _ in drops]
            dropped_by_abi.setdefault(abi, set()).update(dropped)
            for name, kind in drops:
                if kind == "unimplemented":
                    notes.append("%s (kernel ENOSYS on %s)" % (name, table_arch))
                    continue
                notes.append("%s (absent from the libaudit %s table)" % (name, table_arch))
                if key in CRITICAL_KEYS:
                    # A core call missing from the host table means the policy
                    # cannot be confirmed; losing it while the key keeps other
                    # syscalls must not pass the coverage gate.
                    raise Failure(
                        EXIT_ADAPTATION,
                        "critical syscall %r for key %s is not in the libaudit %s "
                        "table (source line %d); cannot confirm it on this host"
                        % (name, key, table_arch, line_number),
                    )
            if emitted is None:
                if key:
                    source_keys[key] += 1
                status_counts["skipped"] += 1
                records.append({
                    "source_line": line_number,
                    "key": key,
                    "arch": abi,
                    "status": "skipped",
                    "reason": "no supported syscall left: %s" % "; ".join(notes),
                    "generated_lines": [],
                    "dropped_syscalls": dropped,
                })
                continue
            tokens = emitted

        missing = [
            target for target in path_filters(tokens)
            if not path_exists(facts["sysroot"], target)
        ]
        if missing:
            if key:
                source_keys[key] += 1
            status_counts["skipped"] += 1
            records.append({
                "source_line": line_number,
                "key": key,
                "arch": abi,
                "status": "skipped",
                "reason": "missing path on this host: %s" % ", ".join(missing),
                "generated_lines": [],
                "dropped_syscalls": dropped,
            })
            continue

        tokens, uid_changed = substitute_uid(tokens, facts["uid_min"])
        reasons = []
        if notes:
            reasons.append("dropped syscalls: " + "; ".join(notes))
        if uid_changed:
            reasons.append(
                "auid>=1000 replaced with the host UID_MIN auid>=%d" % facts["uid_min"])
        status = "adapted" if reasons else "kept"
        reason = ", ".join(reasons) if reasons else "unchanged"

        if key:
            source_keys[key] += 1
            generated_keys[key] += 1
        status_counts[status] += 1
        out_lines.append(" ".join(tokens))
        records.append({
            "source_line": line_number,
            "key": key,
            "arch": abi,
            "status": status,
            "reason": reason,
            "generated_lines": [len(out_lines)],
            "dropped_syscalls": dropped,
        })

    # Self-check on the generated text: no rule may still filter on a syscall
    # that was dropped for its own ABI (a name dropped on the native ABI may
    # legitimately stay on the 32-bit compat ABI).
    generated_text = "\n".join(out_lines) + "\n"
    violations = []
    for line in out_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        line_abi = None
        for index, token in enumerate(fields[:-1]):
            if token == "-F" and fields[index + 1].startswith("arch="):
                line_abi = fields[index + 1][5:]
        blocked = dropped_by_abi.get(line_abi, set())
        for index, token in enumerate(fields[:-1]):
            if token != "-S":
                continue
            for name in fields[index + 1].split(","):
                if name in blocked:
                    violations.append("%s (%s)" % (name, line_abi))
    if violations:
        raise Failure(
            EXIT_ADAPTATION,
            "generated rules still carry unsupported syscalls: %s"
            % ", ".join(sorted(set(violations))),
        )
    if facts["uid_min"] != 1000:
        stale = [
            line for line in out_lines
            if not line.strip().startswith("#")
            and AUID_THRESHOLD_TOKEN in line.split()
        ]
        if stale:
            raise Failure(
                EXIT_ADAPTATION,
                "generated rules still contain %s although UID_MIN=%d: %s"
                % (AUID_THRESHOLD_TOKEN, facts["uid_min"], stale[0].strip()),
            )

    zero_keys = [key for key in CRITICAL_KEYS if source_keys[key] and not generated_keys[key]]
    if zero_keys:
        raise Failure(
            EXIT_ADAPTATION,
            "critical keys lost all their rules: %s (see the skip reasons in the "
            "report; refusing to publish an incomplete baseline)"
            % ", ".join(zero_keys),
        )
    missing_critical = [key for key in CRITICAL_KEYS if not generated_keys[key]]
    if missing_critical:
        raise Failure(
            EXIT_ADAPTATION,
            "critical keys missing from the source policy: %s"
            % ", ".join(missing_critical),
        )

    generated_sha = hashlib.sha256(generated_text.encode("utf-8")).hexdigest()

    key_summary = {}
    for key in sorted(set(source_keys) | set(generated_keys)):
        key_summary[key] = {
            "source_rules": source_keys[key],
            "generated_rules": generated_keys[key],
        }
    dropped_keys = [key for key, counts in key_summary.items() if counts["generated_rules"] == 0]

    coverage = {
        "host": facts["hostname"],
        "architecture": facts["arch"],
        "kernel": facts["kernel"],
        "audit_version": facts["audit_version"],
        "source_sha256": source_sha,
        "generated_sha256": generated_sha,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_file": str(args.source),
        "generated_file": RULES_NAME,
        "os_release": {
            "id": facts["distro_id"],
            "version_id": facts["distro_version"],
            "pretty_name": facts["distro"],
        },
        "uid_min": facts["uid_min"],
        "kernel_cmdline": facts["kernel_cmdline"],
        "audit_boot_parameter": facts["audit_boot_parameter"],
        "audit_status": facts["audit_status"],
        "abi_tables": {
            abi: {
                "libaudit_table": abi_tables[abi],
                "syscall_names": len(tables.get(abi, {})),
                "unimplemented_names_dropped": sorted(
                    unimplemented_for(abi_tables[abi])),
            }
            for abi in sorted(abi_tables)
        },
        "counts": {
            "kept": status_counts["kept"],
            "adapted": status_counts["adapted"],
            "skipped": status_counts["skipped"],
            "generated_rule_lines": sum(
                1 for line in out_lines
                if line.strip() and not line.strip().startswith("#")
            ),
        },
        "key_summary": key_summary,
        "keys_without_rules": dropped_keys,
        "critical_keys": {key: generated_keys[key] for key in CRITICAL_KEYS},
        "rules": records,
    }
    # Publish the pair atomically: build both files inside a private random
    # staging directory, then rename that directory into place in one step.
    # A per-file replace would let two concurrent runs (or a failure between
    # the two replaces) leave rules and coverage that do not belong together,
    # and the collision guard would then block every retry.
    staging = None
    coverage_text = json.dumps(
        coverage, indent=2, sort_keys=False, ensure_ascii=False) + "\n"
    try:
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(
            dir=str(output_dir.parent), prefix="." + output_dir.name + ".", suffix=".tmp"))
        (staging / RULES_NAME).write_text(generated_text, encoding="utf-8")
        (staging / COVERAGE_NAME).write_text(coverage_text, encoding="utf-8")
        os.chmod(str(staging), 0o755)
        try:
            publish_directory(staging, output_dir)
        except OSError as exc:
            if exc.errno in (errno.EEXIST, errno.ENOTEMPTY, errno.ENOTDIR,
                             errno.EISDIR):
                raise Failure(
                    EXIT_OUTPUT_EXISTS,
                    "%s appeared while generating and was not replaced (%s); "
                    "move it away and rerun. Nothing was published."
                    % (output_dir, exc))
            raise Failure(
                EXIT_ENV,
                "cannot publish the artifacts into %s: %s. Nothing was published."
                % (output_dir, exc))
        staging = None
    except OSError as exc:
        raise Failure(
            EXIT_ENV, "cannot write the artifacts into %s: %s" % (output_dir, exc))
    finally:
        if staging is not None:
            shutil.rmtree(str(staging), ignore_errors=True)

    print("host:        %s (%s)" % (facts["hostname"], facts["distro"]))
    print("kernel:      %s  arch: %s" % (facts["kernel"], facts["arch"]))
    print("audit:       %s, boot param %s, UID_MIN=%d"
          % (facts["audit_version"], facts["audit_boot_parameter"], facts["uid_min"]))
    print("rules:       %d kept, %d adapted, %d skipped"
          % (status_counts["kept"], status_counts["adapted"], status_counts["skipped"]))
    print("generated:   %s (sha256=%s)" % (rules_path, generated_sha))
    print("coverage:    %s" % coverage_path)
    if dropped_keys:
        print("NOTE: keys without any generated rule (vendor/optional paths): %s"
              % ", ".join(dropped_keys))
    print("Next: read coverage.json, then deploy per the auditd-rules-install skill "
          "(backup + conflict scan before loading).")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate Kylin V10 auditd rules with a traceable coverage report.",
    )
    parser.add_argument("--source", default="audit.rules",
                       help="policy source rules (default: audit.rules)")
    parser.add_argument("--output-dir", required=True,
                       help="new directory for 99-dayu.rules and coverage.json")
    parser.add_argument("--sysroot", default="/",
                       help="fixture root for the test-suite only (default: /)")
    parser.add_argument("--arch", choices=sorted(ARCH_ABI_TABLES),
                       help="fixture architecture override; rejected on a live host")
    args = parser.parse_args(argv)
    try:
        return generate(args)
    except Failure as exc:
        sys.stderr.write("FAILED (%d): %s\n" % (exc.code, exc.message))
        return exc.code


if __name__ == "__main__":
    sys.exit(main())
