#!/bin/sh
# Locate the watchdeck binary and hand it the hook JSON on stdin
# (PreToolUse, PermissionDenied, SessionStart, SessionEnd, UserPromptSubmit).
# Missing binary → exit 0 with no output, so Bash is never blocked by an
# incomplete install. The binary itself decides allow/ask/rewrite.
#
# A PATH entry that is relative, or lies under the project (cwd) or $TMPDIR,
# is skipped (review 2026-10-14): a sandboxed skill script may write there,
# and PATH often holds a project dir (.venv/bin, node_modules/.bin), so a
# planted copy would otherwise answer every later hook event unsandboxed.
# The mod's locateBinary refuses the same places.
under() { # under <dir> <root>: dir is root or below it
  [ -n "$2" ] || return 1
  case "$1/" in "${2%/}"/*) return 0 ;; esac
  return 1
}
# The physical cwd and TMPDIR are computed once, not per PATH entry: this
# runs on every hook event.
cwd_phys=$(pwd -P)
tmp_phys=
if [ -n "${TMPDIR:-}" ]; then
  tmp_phys=$(cd "$TMPDIR" 2>/dev/null && pwd -P)
fi
unsafe_dir() {
  phys=$(cd "$1" 2>/dev/null && pwd -P) || return 0
  for root in "$PWD" "$cwd_phys" "${TMPDIR:-}" "$tmp_phys"; do
    if under "$1" "$root" || under "$phys" "$root"; then
      return 0
    fi
  done
  return 1
}
set -f # PATH entries are not globs
oldifs=$IFS
IFS=:
for dir in $PATH; do
  IFS=$oldifs
  case "$dir" in /*) ;; *) continue ;; esac
  if [ -f "$dir/watchdeck" ] && [ -x "$dir/watchdeck" ] && ! unsafe_dir "$dir"; then
    exec "$dir/watchdeck" hook
  fi
done
IFS=$oldifs
for candidate in "$HOME/.local/share/watchdeck/bin/watchdeck" "/opt/homebrew/bin/watchdeck" "/usr/local/bin/watchdeck"; do
  if [ -x "$candidate" ]; then
    exec "$candidate" hook
  fi
done
exit 0
