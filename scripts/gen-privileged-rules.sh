#!/usr/bin/env bash
# Generate linux-audit 31-privileged style watches for SUID/SGID/filecap binaries.
# Output is meant for /etc/audit/rules.d/99-privileged.rules (must sort
# after the -D-bearing 99-dayu.rules; augenrules concatenates by name)
# Do NOT use -S setuid,setgid,setresuid,setresgid — those are process-start noise.
#
# Exit status: 0 = every scan ran; 1 = at least one scan failed and the emitted
# rules are incomplete. Callers must treat 1 as "do not deploy".
set -euo pipefail

uid_min="${UID_MIN:-$(awk '$1=="UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null || true)}"
uid_min="${uid_min:-1000}"

scan_failures=0
rule_count=0

warn() {
  printf '## WARNING: %s\n' "$1" >&2
}

fail_scan() {
  scan_failures=$((scan_failures + 1))
  warn "$1"
}

emit() {
  local path="$1"
  [[ -n "$path" ]] || return 0
  printf -- '-a always,exit -F arch=b64 -F path=%s -F perm=x -F auid>=%s -F auid!=unset -F key=privileged\n' "$path" "$uid_min"
  rule_count=$((rule_count + 1))
}

echo "## Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) UID_MIN=${uid_min}"
echo "## Regenerated on each host; do not edit by hand."

# A partially unreadable directory must not truncate the whole rule set: warn on
# stderr (stdout is the rules file), keep what was found, and report failure at
# the end so the caller does not deploy an incomplete file.
scan_perm() {
  local dir="$1" permission="$2" matches
  if ! matches="$(find "$dir" -maxdepth 1 -type f -perm "-$permission" -print 2>/dev/null | sort)"; then
    fail_scan "could not fully scan $dir for -perm $permission"
  fi
  while read -r path; do
    emit "$path"
  done <<< "$matches"
}

for dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
  [[ -d "$dir" ]] || continue
  scan_perm "$dir" 04000
  scan_perm "$dir" 02000
done

# filecap rejects symlinked directories (e.g. /bin -> /usr/bin on usrmerge
# hosts) and needs one real directory per call, so scan each real directory.
if command -v filecap >/dev/null 2>&1; then
  for dir in /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /bin /sbin; do
    [[ -d "$dir" && ! -L "$dir" ]] || continue
    if ! caps="$(filecap "$dir" 2>/dev/null)"; then
      fail_scan "filecap could not scan $dir"
      continue
    fi
    # Parse in the foreground: a failure in the pipeline must reach the exit
    # status, which process substitution would hide from pipefail.
    if ! paths="$(printf '%s\n' "$caps" | awk 'NR>1 && $2 ~ /^\// { print $2 }' | sort -u)"; then
      fail_scan "could not parse filecap output for $dir"
      continue
    fi
    while read -r path; do
      emit "$path"
    done <<< "$paths"
  done
fi

if (( rule_count == 0 )); then
  warn "no SUID/SGID/filecap binaries found; 99-privileged.rules carries no rules"
fi
if (( scan_failures > 0 )); then
  warn "$scan_failures privileged scan(s) failed; generated rules are incomplete — do not deploy"
  exit 1
fi
