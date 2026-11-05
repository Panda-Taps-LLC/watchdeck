#!/bin/sh
# Tests scripts/install.sh against a fake local release. No network. Every
# location watchdeck or Claude Code reads (HOME, XDG dirs, CLAUDE_CONFIG_DIR,
# the activity log) points into the temp dir, so the real settings are never
# touched.
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/sp-install-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

case "$(uname -s)" in Darwin) os=darwin ;; *) os=linux ;; esac
case "$(uname -m)" in arm64 | aarch64) arch=arm64 ;; *) arch=amd64 ;; esac
ver=9.9.9
archive="watchdeck_${ver}_${os}_${arch}.tar.gz"

mkdir "$tmp/rel" "$tmp/stage"
(cd "$root" && go build -ldflags "-X main.version=$ver" -o "$tmp/stage/watchdeck" ./cmd/watchdeck)
tar -czf "$tmp/rel/$archive" -C "$tmp/stage" watchdeck
if command -v sha256sum >/dev/null 2>&1; then
	sum="$(sha256sum "$tmp/rel/$archive" | awk '{print $1}')"
else
	sum="$(shasum -a 256 "$tmp/rel/$archive" | awk '{print $1}')"
fi
echo "$sum  $archive" >"$tmp/rel/checksums.txt"

# Built above with the real environment (go needs its caches); from here on
# nothing may see the real home.
export HOME="$tmp/home" XDG_CONFIG_HOME="$tmp/home/.config" XDG_STATE_HOME="$tmp/home/.local/state" \
	XDG_CACHE_HOME="$tmp/home/.cache" CLAUDE_CONFIG_DIR="$tmp/home/.claude" WATCHDECK_ACTIVITY="$tmp/activity.jsonl"
mkdir -p "$HOME" "$CLAUDE_CONFIG_DIR"
# The verify cases set WATCHDECK_VERIFY themselves; the developer's value must
# not turn it on in the other cases, which would reach the real GitHub CLI.
unset WATCHDECK_VERIFY

# Stubs for the verify cases (9-14): sh scripts named exactly gh and cosign,
# first on PATH so the real GitHub CLI is never reached. Each appends its name
# and argv to $STUB_LOG, prints $STUB_ERR to stderr when set, and exits per
# $STUB_RC; `gh auth status` exits per $STUB_AUTH_RC. $tmp/stubs-gh holds gh
# alone; $tmp/minbin holds only the tools the installer needs before the
# verify step, for the case where neither tool is on PATH (GitHub's ubuntu
# runners have gh in /usr/bin, so a trimmed system PATH is not enough).
export STUB_LOG="$tmp/stub.log"
mkdir "$tmp/stubs" "$tmp/stubs-gh" "$tmp/minbin"
for t in gh cosign; do
	cat >"$tmp/stubs/$t" <<'STUB'
#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >>"$STUB_LOG"
[ -z "${STUB_ERR:-}" ] || echo "$STUB_ERR" >&2
case "${1:-} ${2:-}" in "auth status") exit "${STUB_AUTH_RC:-0}" ;; esac
exit "${STUB_RC:-0}"
STUB
	chmod 0755 "$tmp/stubs/$t"
done
cp -p "$tmp/stubs/gh" "$tmp/stubs-gh/gh"
for t in sh uname mktemp grep cp rm; do ln -s "$(command -v "$t")" "$tmp/minbin/$t"; done
[ "$(PATH="$tmp/stubs:$PATH" command -v gh)" = "$tmp/stubs/gh" ] || fail "the gh stub is not first on PATH"
[ "$(PATH="$tmp/minbin" command -v gh || true)" = "" ] || fail "gh is reachable from the minimal PATH"

# 1. good release installs and runs (local directory base)
sh "$root/scripts/install.sh" --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin" >"$tmp/out1" 2>&1 || { cat "$tmp/out1"; fail "install failed"; }
[ -x "$tmp/bin/watchdeck" ] || fail "binary not installed"
"$tmp/bin/watchdeck" version | grep -q "$ver" || fail "version output lacks $ver"
grep -q "Next: watchdeck setup" "$tmp/out1" || fail "next-step hint missing"
grep -q "To remove everything later: watchdeck uninstall" "$tmp/out1" || fail "uninstall hint missing"
grep -q "Not verified against the release signature; add --verify" "$tmp/out1" || fail "no not-verified line without --verify"
[ ! -e "$CLAUDE_CONFIG_DIR/settings.json" ] || fail "--no-setup wrote settings"
echo "ok: install from a local directory"

# 2. file:// base
sh "$root/scripts/install.sh" --version "v$ver" --no-setup --from "file://$tmp/rel" --dir "$tmp/bin2" >/dev/null 2>&1 || fail "file:// install failed"
[ -x "$tmp/bin2/watchdeck" ] || fail "file:// binary missing"
echo "ok: file:// base"

# 3. tampered checksum is refused and installs nothing
echo "0000000000000000000000000000000000000000000000000000000000000000  $archive" >"$tmp/rel/checksums.txt"
if sh "$root/scripts/install.sh" --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin3" >"$tmp/out3" 2>&1; then fail "tampered checksum accepted"; fi
grep -q "checksum mismatch" "$tmp/out3" || fail "no mismatch message"
[ ! -e "$tmp/bin3/watchdeck" ] || fail "binary installed despite mismatch"
echo "ok: tampered checksum refused"

# 4. bad version string refused
for v in 0.1.0 'v1/../../../x' 'v1.2.3/..' 'v1.2' 'v1.2.3 x'; do
	if sh "$root/scripts/install.sh" --no-setup --version "$v" --from "$tmp/rel" --dir "$tmp/bin4" >"$tmp/out4" 2>&1; then fail "bad version accepted: $v"; fi
	grep -q "version must look like" "$tmp/out4" || fail "no version error for: $v"
done
[ ! -e "$tmp/bin4" ] || fail "dir created for bad version"
echo "ok: bad and traversal versions refused"

# 5. archive missing from checksums.txt
echo "$sum  other.tar.gz" >"$tmp/rel/checksums.txt"
if sh "$root/scripts/install.sh" --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin5" >"$tmp/out5" 2>&1; then fail "unlisted archive accepted"; fi
grep -q "not listed" "$tmp/out5" || fail "no not-listed message"
echo "ok: archive missing from checksums refused"

# 6. relative --from without ./
echo "$sum  $archive" >"$tmp/rel/checksums.txt"
(cd "$tmp" && sh "$root/scripts/install.sh" --no-setup --version "v$ver" --from rel --dir "$tmp/bin6" >/dev/null 2>&1) || fail "relative --from failed"
[ -x "$tmp/bin6/watchdeck" ] || fail "relative --from binary missing"
echo "ok: relative --from"

# 7. default dir, ~/.local/bin link, setup --yes into the temp settings, then
# uninstall --yes takes it all out again (the binary last)
[ ! -e "$CLAUDE_CONFIG_DIR/settings.json" ] || fail "settings written before case 7"
(cd "$tmp" && PATH="$HOME/.local/bin:$PATH" sh "$root/scripts/install.sh" --yes --version "v$ver" --from "$tmp/rel" >"$tmp/out7" 2>&1) || { cat "$tmp/out7"; fail "install --yes failed"; }
inst="$HOME/.local/share/watchdeck/bin/watchdeck"
[ -x "$inst" ] || fail "binary not in the default dir"
[ -L "$HOME/.local/bin/watchdeck" ] || { cat "$tmp/out7"; fail "no ~/.local/bin link"; }
grep -q "Running: watchdeck setup --yes" "$tmp/out7" || { cat "$tmp/out7"; fail "setup not run"; }
if grep -q "Enforcement does not work on this machine" "$tmp/out7"; then
	# setup writes nothing when the sandbox self-test fails (e.g. Linux without bwrap)
	[ ! -e "$CLAUDE_CONFIG_DIR/settings.json" ] || fail "setup wrote settings after a failed self-test"
	rm -f "$HOME/.local/bin/watchdeck" "$inst"
	echo "skip: install --yes hooks check (the sandbox self-test fails on this machine)"
else
	grep -q '"command": ".*/share/watchdeck/bin/watchdeck"' "$CLAUDE_CONFIG_DIR/settings.json" || { cat "$tmp/out7"; fail "hooks not in the temp settings"; }
	grep -q "watchdeck run \*" "$CLAUDE_CONFIG_DIR/settings.json" || fail "sandbox exclusion not in the temp settings"
	(cd "$tmp" && "$HOME/.local/bin/watchdeck" uninstall --yes >"$tmp/out7u" 2>&1) || { cat "$tmp/out7u"; fail "uninstall --yes failed"; }
	if grep -q "watchdeck" "$CLAUDE_CONFIG_DIR/settings.json"; then cat "$CLAUDE_CONFIG_DIR/settings.json"; fail "uninstall left watchdeck in the settings"; fi
	[ ! -e "$inst" ] || fail "uninstall left the installed binary"
	[ ! -L "$HOME/.local/bin/watchdeck" ] || fail "uninstall left the link"
	echo "ok: install --yes runs setup in the temp home; uninstall --yes removes it"
fi

# 8. a real file in ~/.local/bin is never replaced by the link
mkdir -p "$HOME/.local/bin"
echo "not ours" >"$HOME/.local/bin/watchdeck"
PATH="$HOME/.local/bin:$PATH" sh "$root/scripts/install.sh" --no-setup --version "v$ver" --from "$tmp/rel" >"$tmp/out8" 2>&1 || { cat "$tmp/out8"; fail "install failed"; }
[ "$(cat "$HOME/.local/bin/watchdeck")" = "not ours" ] || fail "a regular file in ~/.local/bin was overwritten"
grep -q "Not linking" "$tmp/out8" || fail "no not-linking message"
echo "ok: a regular file in ~/.local/bin is left alone"

# 9. --verify with gh signed in and the attestation passing installs; the gh
# line names the repository and the signer workflow; no "Not verified" line
rm -f "$STUB_LOG"
PATH="$tmp/stubs:$PATH" STUB_RC=0 STUB_AUTH_RC=0 sh "$root/scripts/install.sh" --verify --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin9" >"$tmp/out9" 2>&1 || { cat "$tmp/out9"; fail "--verify install failed"; }
[ -x "$tmp/bin9/watchdeck" ] || fail "--verify binary missing"
grep -q "provenance ok" "$tmp/out9" || { cat "$tmp/out9"; fail "no provenance ok line"; }
grep -q "^gh auth status$" "$STUB_LOG" || { cat "$STUB_LOG"; fail "gh auth status not checked"; }
grep -q "^gh attestation verify .*/$archive --repo Panda-Taps-LLC/watchdeck --signer-workflow Panda-Taps-LLC/watchdeck/.github/workflows/release.yml$" "$STUB_LOG" || { cat "$STUB_LOG"; fail "gh attestation verify line wrong"; }
if grep -q "^cosign" "$STUB_LOG"; then fail "cosign called although gh verified"; fi
if grep -q "Not verified" "$tmp/out9"; then fail "Not verified line printed after a verify"; fi
echo "ok: --verify with gh signed in installs"

# 10. gh verify fails: nothing installed, the message names the reason
rm -f "$STUB_LOG"
if PATH="$tmp/stubs:$PATH" STUB_RC=1 STUB_AUTH_RC=0 STUB_ERR="stub: no attestations found" sh "$root/scripts/install.sh" --verify --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin10" >"$tmp/out10" 2>&1; then fail "gh verify failure accepted"; fi
grep -Fq "provenance could not be verified for $archive (gh attestation): stub: no attestations found; nothing installed" "$tmp/out10" || { cat "$tmp/out10"; fail "no provenance failure message"; }
[ ! -e "$tmp/bin10" ] || fail "dir created despite a failed provenance check"
if grep -q "^cosign" "$STUB_LOG"; then fail "cosign tried after gh failed"; fi
# the real gh prints a blank line before "Error: …": the message carries the
# first non-blank stderr line
if PATH="$tmp/stubs:$PATH" STUB_RC=1 STUB_AUTH_RC=0 STUB_ERR="$(printf '\nError: no attestations found')" sh "$root/scripts/install.sh" --verify --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin10b" >"$tmp/out10b" 2>&1; then fail "gh verify failure with a blank first line accepted"; fi
grep -Fq "provenance could not be verified for $archive (gh attestation): Error: no attestations found; nothing installed" "$tmp/out10b" || { cat "$tmp/out10b"; fail "message does not carry the first non-blank stderr line"; }
[ ! -e "$tmp/bin10b" ] || fail "dir created despite a failed provenance check (blank line)"
echo "ok: a failed gh verify installs nothing"

# 11. gh not signed in, cosign stub passes, bundle present: installs; the
# cosign line carries the bundle, the identity for this tag and checksums.txt
printf '{"stub": "not a real bundle"}\n' >"$tmp/rel/checksums.txt.sigstore.json"
rm -f "$STUB_LOG"
PATH="$tmp/stubs:$PATH" STUB_RC=0 STUB_AUTH_RC=1 sh "$root/scripts/install.sh" --verify --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin11" >"$tmp/out11" 2>&1 || { cat "$tmp/out11"; fail "--verify via cosign failed"; }
[ -x "$tmp/bin11/watchdeck" ] || fail "cosign-verified binary missing"
grep -q "signature ok" "$tmp/out11" || { cat "$tmp/out11"; fail "no signature ok line"; }
grep -q "^cosign verify-blob --bundle .*/checksums.txt.sigstore.json --certificate-identity https://github.com/Panda-Taps-LLC/watchdeck/.github/workflows/release.yml@refs/tags/v$ver --certificate-oidc-issuer https://token.actions.githubusercontent.com .*/checksums.txt$" "$STUB_LOG" || { cat "$STUB_LOG"; fail "cosign verify-blob line wrong"; }
if grep -q "^gh attestation" "$STUB_LOG"; then fail "gh attestation verify called while not signed in"; fi
# a failed cosign verify installs nothing; the message carries the first
# non-blank stderr line
rm -f "$STUB_LOG"
if PATH="$tmp/stubs:$PATH" STUB_RC=1 STUB_AUTH_RC=1 STUB_ERR="$(printf '\nstub: certificate identity mismatch')" sh "$root/scripts/install.sh" --verify --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin11b" >"$tmp/out11b" 2>&1; then fail "cosign verify failure accepted"; fi
grep -Fq "signature could not be verified for checksums.txt (cosign bundle): stub: certificate identity mismatch; nothing installed" "$tmp/out11b" || { cat "$tmp/out11b"; fail "no signature failure message"; }
[ ! -e "$tmp/bin11b" ] || fail "dir created despite a failed signature check"
grep -q "^cosign verify-blob" "$STUB_LOG" || fail "cosign not run for the failing case"
echo "ok: --verify falls back to cosign when gh is not signed in"

# 12. neither tool on PATH: nothing installed, the message names both; gh
# present but not signed in and no cosign: likewise, naming the state
if PATH="$tmp/minbin" sh "$root/scripts/install.sh" --verify --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin12" >"$tmp/out12" 2>&1; then fail "--verify without tools accepted"; fi
grep -Fq -- "--verify needs the GitHub CLI signed in (gh auth login) or cosign 3.x" "$tmp/out12" || { cat "$tmp/out12"; fail "no needs-a-tool message"; }
grep -q "gh is not installed" "$tmp/out12" || { cat "$tmp/out12"; fail "message does not name gh"; }
grep -q "cosign is not installed" "$tmp/out12" || { cat "$tmp/out12"; fail "message does not name cosign"; }
grep -q "nothing installed" "$tmp/out12" || fail "no nothing-installed in the message"
[ ! -e "$tmp/bin12" ] || fail "dir created without a verify tool"
rm -f "$STUB_LOG"
if PATH="$tmp/stubs-gh:$tmp/minbin" STUB_AUTH_RC=1 sh "$root/scripts/install.sh" --verify --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin12b" >"$tmp/out12b" 2>&1; then fail "--verify with gh signed out and no cosign accepted"; fi
grep -q "gh is installed but not signed in" "$tmp/out12b" || { cat "$tmp/out12b"; fail "message does not say gh is signed out"; }
grep -q "cosign is not installed" "$tmp/out12b" || { cat "$tmp/out12b"; fail "message does not name cosign (gh signed out)"; }
grep -q "^gh auth status$" "$STUB_LOG" || fail "gh auth status not checked (gh signed out)"
if grep -q "^gh attestation" "$STUB_LOG"; then fail "gh attestation verify called while signed out"; fi
[ ! -e "$tmp/bin12b" ] || fail "dir created with gh signed out and no cosign"
echo "ok: --verify without a usable tool installs nothing and names both"

# 13. WATCHDECK_VERIFY=1 equals the flag; cosign with the bundle missing from
# the release is an unsigned draft: nothing installed, cosign never run
rm -f "$tmp/rel/checksums.txt.sigstore.json" "$STUB_LOG"
if PATH="$tmp/stubs:$PATH" WATCHDECK_VERIFY=1 STUB_RC=0 STUB_AUTH_RC=1 sh "$root/scripts/install.sh" --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin13" >"$tmp/out13" 2>&1; then fail "unsigned draft accepted under WATCHDECK_VERIFY=1"; fi
grep -Fq "no checksums.txt.sigstore.json in the release: an unsigned draft; nothing installed" "$tmp/out13" || { cat "$tmp/out13"; fail "no unsigned-draft message"; }
[ ! -e "$tmp/bin13" ] || fail "dir created for an unsigned draft"
if grep -q "^cosign" "$STUB_LOG"; then fail "cosign run without a bundle"; fi
echo "ok: WATCHDECK_VERIFY=1 turns verify on; a missing bundle is an unsigned draft"

# 14. a tampered checksum is still refused after a passing verify (verify
# first, then sha256)
echo "0000000000000000000000000000000000000000000000000000000000000000  $archive" >"$tmp/rel/checksums.txt"
rm -f "$STUB_LOG"
if PATH="$tmp/stubs:$PATH" STUB_RC=0 STUB_AUTH_RC=0 sh "$root/scripts/install.sh" --verify --no-setup --version "v$ver" --from "$tmp/rel" --dir "$tmp/bin14" >"$tmp/out14" 2>&1; then fail "tampered checksum accepted after a passing verify"; fi
grep -q "provenance ok" "$tmp/out14" || { cat "$tmp/out14"; fail "verify did not run before the checksum"; }
grep -q "checksum mismatch" "$tmp/out14" || { cat "$tmp/out14"; fail "no mismatch message after verify"; }
[ ! -e "$tmp/bin14" ] || fail "binary installed despite mismatch after verify"
echo "$sum  $archive" >"$tmp/rel/checksums.txt"
echo "ok: sha256 still checked after a passing verify"
echo "PASS"
