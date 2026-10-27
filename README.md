[![Actively Maintained](https://img.shields.io/badge/Maintenance%20Level-Actively%20Maintained-green.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

        ___             ___ __      __
       /   | __  ______/ (_) /_____/ /
      / /| |/ / / / __  / / __/ __  / 
     / ___ / /_/ / /_/ / / /_/ /_/ /  
    /_/  |_\__,_/\__,_/_/\__/\__,_/   

Best Practice Auditd Configuration

**dayu-sec fork** of [Neo23x0/auditd](https://github.com/Neo23x0/auditd). High-volume defaults (`execve`, `connect`, `socket`, 32-bit `-S all`) are **off**. See [DAYU.md](DAYU.md) for what changed, why, and how to deploy. Rebase onto upstream `master`; keep local edits on the `dayu` branch.

## Idea

The idea of this auditd configuration is to provide a best-practice baseline that

- is designed to load out-of-the-box on major Linux distributions
- covers a broad set of security-relevant host activity
- prefers reusable telemetry over long lists of hard-coded detections
- keeps the detection logic in Sigma rules, SIEM content, or host-side analytics
- stays easy to read and adapt through sectioning and comments

The simplified ruleset intentionally keeps some high-value but potentially
high-volume telemetry, especially process creation, socket creation, and file
access failure events. Tune these sections to your environment if needed.

## Coverage

The current configuration focuses on the following coverage areas:

- self-auditing and audit configuration integrity
- noise filters and portability-oriented exclusions
- kernel, module, mount, swap, and time changes
- scheduled tasks, account databases, PAM, sudo, and login state
- network, firewall, startup, service, and boot-path configuration
- library paths, shell profiles, SSH, systemd, and MAC policy changes
- failed access attempts, DAC modifications, session files, and privilege-abuse heuristics
- special primitives such as `ptrace`, `memfd_create`, `bpf`, namespaces, `io_uring`, and `userfaultfd`
- software, container, and security-tooling configuration paths
- high-volume telemetry such as `execve`, `execveat`, socket creation, file deletion, and 32-bit ABI usage

## Related Projects

This ruleset is intended to stay agnostic of the downstream detection logic.
It focuses on collecting broadly useful audit telemetry that can then be
analyzed in different ways, for example with Sigma-based tooling or SIEM
queries.

One open source project that can make use of this audit data is
[Aurora Linux](https://github.com/Nextron-Labs/aurora-linux), a lightweight
and customizable Sigma-based agent for Linux that combines eBPF-based telemetry
with user-space enrichment and Sigma rule matching.

## Validation

This ruleset intentionally includes `-i` so that optional distro-specific paths
do not abort loading on systems where some binaries or directories are absent.
This keeps the default deployment simple, but it also means rule load errors are
ignored.

If you want a strict pre-deployment validation, test a temporary copy with the
`-i` line removed, for example:

```bash
grep -v '^-i$' audit.rules > /tmp/audit.rules.strict
auditctl -R /tmp/audit.rules.strict
```

The repository also includes GitHub Actions checks that lint the rules and
validate that a portable CI copy and a strict copy can both be loaded on Ubuntu.

## Kylin V10

Kylin V10 ships a 4.19 kernel whose audit behaviour differs from the Ubuntu and
RHEL hosts this baseline was developed on: `openat2` is not implemented at all,
and the libaudit tables list legacy aarch64 names (`open`, `chmod`, `unlink`, ...)
that the native ABI answers with `ENOSYS`. Because a single unknown syscall
prevents a whole rule from loading — and `-i` hides that failure — Kylin hosts
must not load `audit.rules` as-is.

Generate the adapted rules on the target host instead:

```bash
python3 scripts/prepare-kylin-rules.py --source audit.rules --output-dir /var/tmp/dayu-kylin
```

The output path must not exist yet: both artifacts are written inside a private
staging directory and published with an atomic no-replace directory rename
(`renameat2`; the tool fails rather than degrading to per-file writes), so a
concurrent run, a late-created path or a write failure cannot leave rules and
report that disagree. Generate privileged watches separately with
`scripts/gen-privileged-rules.sh` (per host) — it exits non-zero when a scan was
incomplete, and that must stop the deployment.

The tool is read-only: it records the host facts, refuses anything but a Kylin
V10 4.19 host, resolves every `-S` against the host's own libaudit ABI tables
(`ausyscall <arch> --dump`), drops names the *kernel* cannot run even when the
table lists them (`openat2`, and the aarch64 legacy stubs for the native ABI),
skips and reports missing `-w`/`dir=`/`exe=` targets, rewrites `auid>=1000` to
the host `UID_MIN` on every rule (including rules without `-S`), removes `-i`,
and writes `99-dayu.rules` plus a per-rule `coverage.json` (source line, key,
kept/adapted/skipped, reason, generated line). It never loads rules, never
touches boot parameters and never restarts the host; `audit=0` aborts with the
maintenance-window action instead of pretending the kernel lacks audit support.

On a Kylin V10 aarch64 host that already ran the unadapted baseline, 224 rules
were loaded and none of the ten failed-access rules were: `openat2` made each whole
rule fail while `-i` hid it. The adapted artifact keeps the same policy in 174
directive lines with `unauthedfileaccess` back at 10 rules; a strict load on an
isolated Kylin host is still pending (see `DAYU.md`).

A generation fails (exit 4) when a key that must survive — `process_creation_user`,
`process_creation_bash`, `unauthedfileaccess`, `perm_mod`, `delete` — loses all of
its rules, or when one of its core syscalls cannot be confirmed in the host ABI
table (a surviving `execveat` does not compensate for a missing `execve`), or when
an ABI table cannot be confirmed. Deployment, conflict scanning,
isolated validation and rollback are described in
`.agents/skills/auditd-rules-install/SKILL.md` and `DAYU.md`.

Before writing into `rules.d`, run the read-only layout scanner — it mirrors the
`augenrules` concatenation order (`ls -1v`) and reports a `-D` that runs after
rules were added, byte-identical duplicate watches (kernel answers `Rule exists`
and the whole load aborts), same-watch-different-key overlap, leftover `-i`, and
multiple `-D` files:

```bash
bash scripts/preflight-rulesd.sh /etc/audit/rules.d
```

Fixture tests (no Kylin host required, synthetic sysroots and ABI tables):

```bash
python3 -m unittest discover -s tests
```

## UID_MIN

Several rules in `audit.rules` use `auid>=1000 -F auid!=unset` to focus on
interactive user activity and exclude unset login sessions.

`1000` is the common `UID_MIN` on many Linux distributions, but it is not
universal. If your host uses a different `UID_MIN`, check `/etc/login.defs`
and replace `1000` in `audit.rules` before deployment:

```bash
awk '$1=="UID_MIN" { print $2 }' /etc/login.defs
```

## AF_ALG / Copy Fail Telemetry

On April 29, 2026, Xint published Copy Fail (CVE-2026-31431), a local
privilege-escalation technique that abuses the kernel crypto userspace
interface (`AF_ALG`) together with `splice()` to corrupt page-cache-backed
files in memory.

This ruleset includes a small `af_alg` block to collect the stable, low-noise
parts of that setup from attributable user sessions:

- `socket(AF_ALG, ...)`
- `bind()` using the common fixed-size `struct sockaddr_alg`
- `setsockopt(..., SOL_ALG, ...)`

This is intentionally more generic than a one-off signature for
`authencesn(hmac(sha256),cbc(aes))` because audit syscall filters cannot match
string arguments. In practice, the algorithm name lives in the `SOCKADDR`
record emitted by `bind()`, so the recommended downstream detection is:

- filter on `key=af_alg`
- inspect `SOCKADDR.saddr` / `SADDR={ saddr_fam=alg ... }`
- flag `salg_type=aead` with `salg_name` containing `authencesn(`
- raise severity when the same `pid`, `exe`, or `auid` emits many such binds in
  a short window

The proof-of-concept described by Xint also relies on repeated `splice()`
operations. Those syscalls are too noisy for the default ruleset on many
systems, so the repository ships only a commented-out `splice_user` overlay in
`audit.rules`. Enable it only if `splice` / `vmsplice` are uncommon in your
environment and correlate it with recent `af_alg` activity from the same
process or user session.

## Sources

The configuration is based on the following sources and years of merged
improvements to the default ruleset:

Gov.uk auditd rules
https://github.com/gds-operations/puppet-auditd/pull/1

CentOS 7 hardening
https://highon.coffee/blog/security-harden-centos-7/#auditd---audit-daemon

Linux audit repo 
https://github.com/linux-audit/audit-userspace/tree/master/rules

Auditd high performance linux auditing
https://linux-audit.com/tuning-auditd-high-performance-linux-auditing/

Copy Fail: 732 Bytes to Root on Every Major Linux Distribution.
https://xint.io/blog/copy-fail-linux-distributions

Linux kernel crypto userspace interface (AF_ALG)
https://docs.kernel.org/crypto/userspace-if.html

### Further rules

Not all of these rules have been included. 

For PCI DSS compliance see: 
https://github.com/linux-audit/audit-userspace/blob/master/rules/30-pci-dss-v31.rules

For NISPOM compliance see:
https://github.com/linux-audit/audit-userspace/blob/master/rules/30-nispom.rules

## Video Explanations by IppSec

IppSec captured a video that explains how to detect the exploitation of the
OMIGOD vulnerability using auditd. The core auditd concepts in that video are
still useful, but the ruleset in this repository has since been simplified
significantly. Treat the video as historical background and an introduction to
auditd-based detection ideas, not as line-by-line documentation of the current
`audit.rules`.

https://www.youtube.com/watch?v=lc1i9h1GyMA

## Contribution

Please contribute your changes as pull requests
