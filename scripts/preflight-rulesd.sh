#!/bin/sh
# Report audit rules.d layouts that make `augenrules --load` abort or silently
# drop rules. Read-only: never loads, never edits, never calls auditctl.
#
# Ordering mirrors augenrules on Kylin/RHEL, which concatenates:
#   for rules in $(/bin/ls -1v /etc/audit/rules.d | grep "\.rules$"); do cat ...
#
# Checks:
#   BLOCKER  a -D runs after rules were already added (those rules are deleted)
#   BLOCKER  identical watch added twice (kernel answers EEXIST, load aborts)
#   WARN     same watch path+perm with different keys (allowed, doubles events)
#   WARN     -i present (load errors in that file would be ignored)
#   WARN     more than one file carries -D
#
# Usage: preflight-rulesd.sh [rules-dir]      (default /etc/audit/rules.d)
# Exit:  0 = no blocker (warnings allowed), 1 = blockers, 2 = usage error.

set -u

rules_dir=${1:-/etc/audit/rules.d}
if [ ! -d "$rules_dir" ]; then
  printf 'preflight-rulesd: not a directory: %s\n' "$rules_dir" >&2
  exit 2
fi

# `ls -1v` is what augenrules uses on Linux; keep that ordering where the flag
# exists and fall back to a byte sort only where it does not (e.g. BSD ls).
if /bin/ls -1v /dev/null >/dev/null 2>&1; then
  file_list=$(/bin/ls -1v "$rules_dir" 2>/dev/null | grep '\.rules$')
else
  file_list=$(/bin/ls -1 "$rules_dir" 2>/dev/null | LC_ALL=C sort | grep '\.rules$')
fi

if [ -z "$file_list" ]; then
  printf 'preflight-rulesd: no .rules files in %s\n' "$rules_dir"
  exit 0
fi

printf 'load order:'
printf '%s\n' "$file_list" | while IFS= read -r name; do printf ' %s' "$name"; done
printf '\n'

# Build the argument list with newline-only word splitting so paths with
# spaces survive; ordering is the augenrules order computed above.
old_ifs=$IFS
IFS='
'
set -f
set -- $(printf '%s\n' "$file_list" | sed "s#^#$rules_dir/#")
set +f
IFS=$old_ifs

awk '
function blocker(msg) { blockers++; printf "BLOCKER: %s\n", msg }
function warning(msg) { warnings++; printf "WARN: %s\n", msg }
function sort_chars(text,   n, i, j, out, chars, tmp) {
  n = split(text, chars, "")
  for (i = 1; i <= n; i++)
    for (j = i + 1; j <= n; j++)
      if (chars[j] < chars[i]) { tmp = chars[i]; chars[i] = chars[j]; chars[j] = tmp }
  out = ""
  for (i = 1; i <= n; i++) out = out chars[i]
  return out
}
FNR == 1 {
  file = FILENAME
  sub(/.*\//, "", file)
  if (file in dminus_file) duplicate_dminus = 1
}
/^-D([[:space:]]|$)/ {
  if (!minus_seen) { minus_seen = 1; minus_file = file }
  if (dir_seen) {
    blocker(sprintf("%s contains -D after rules were already added (%s): those rules are deleted again", file, dir_file))
  }
  dminus_file[file] = 1
}
/^-(a|w)([[:space:]]|$)/ {
  if (!minus_seen) { dir_seen = 1; dir_file = file }
}
/^-i([[:space:]]|$)/ { ignore_errors[file] = FNR }
/^-w([[:space:]]|$)/ {
  target = $2
  sub(/\/$/, "", target)
  perm = ""; key = ""
  for (i = 3; i <= NF; i++) {
    if ($i == "-p") perm = $(i + 1)
    else if ($i == "-k") key = $(i + 1)
  }
  perm = sort_chars(perm)
  place = sprintf("%s:%d", file, FNR)
  exact = target "|" perm "|" key
  permid = target "|" perm
  if (exact in seen_exact) {
    blocker(sprintf("identical watch on %s (-p %s, key=%s) at %s and %s: kernel answers \"Rule exists\", load aborts", \
      target, perm, (key == "" ? "none" : key), seen_exact[exact], place))
  } else {
    seen_exact[exact] = place
  }
  if (permid in seen_perm) {
    split(seen_perm[permid], previous, "|")
    if (previous[2] != key) {
      warning(sprintf("%s (-p %s) watched twice with different keys: %s (key=%s) and %s (key=%s); allowed but doubles events", \
        target, perm, previous[1], (previous[2] == "" ? "none" : previous[2]), place, (key == "" ? "none" : key)))
    }
  } else {
    seen_perm[permid] = place "|" key
  }
}
END {
  if (duplicate_dminus) warning("more than one file carries -D")
  for (f in ignore_errors) warning(sprintf("%s contains -i: load errors in this file would be ignored", f))
  printf "summary: %d blocker(s), %d warning(s)\n", blockers, warnings
  if (blockers > 0) {
    printf "preflight-rulesd: resolve blockers before loading; do not delete unknown files without approval\n"
    exit 1
  }
  exit 0
}
' "$@"
