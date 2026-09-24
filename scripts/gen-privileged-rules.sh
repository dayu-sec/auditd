#!/usr/bin/env bash
# Generate linux-audit 31-privileged style watches for SUID/SGID/filecap binaries.
# Output is meant for /etc/audit/rules.d/98-privileged.rules
# Do NOT use -S setuid,setgid,setresuid,setresgid — those are process-start noise.
set -euo pipefail

uid_min="${UID_MIN:-$(awk '$1=="UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null || true)}"
uid_min="${uid_min:-1000}"

emit() {
  local path="$1"
  printf -- '-a always,exit -F arch=b64 -F path=%s -F perm=x -F auid>=%s -F auid!=unset -F key=privileged\n' "$path" "$uid_min"
}

echo "## Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) UID_MIN=${uid_min}"
echo "## Regenerated on each host; do not edit by hand."

for dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
  [[ -d "$dir" ]] || continue
  find "$dir" -maxdepth 1 -type f -perm -04000 -print 2>/dev/null | sort | while read -r p; do
    emit "$p"
  done
  find "$dir" -maxdepth 1 -type f -perm -02000 -print 2>/dev/null | sort | while read -r p; do
    emit "$p"
  done
done

if command -v filecap >/dev/null 2>&1; then
  for dir in /bin /sbin /usr/bin /usr/sbin; do
    filecap "$dir" 2>/dev/null | awk 'NR>1 && $2 ~ /^\// { print $2 }' | sort -u | while read -r p; do
      emit "$p"
    done
  done
fi
