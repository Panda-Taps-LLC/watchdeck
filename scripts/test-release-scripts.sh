#!/bin/sh
# Tests scripts/verify-release.sh and scripts/tap-formula.sh against a fake
# release built here from throwaway archives. No network: `gh` and `cosign`
# are sh stubs named exactly and first on PATH, so the real tools are never
# reached. Every location anything reads (HOME, XDG dirs, CLAUDE_CONFIG_DIR,
# TMPDIR, the GitHub CLI's config) points into the temp dir.
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/wd-release-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
verify="$root/scripts/verify-release.sh"
formula="$root/scripts/tap-formula.sh"
started="$(date +%s)"

case "$(uname -s)" in Darwin) os=darwin ;; *) os=linux ;; esac
case "$(uname -m)" in arm64 | aarch64) arch=arm64 ;; *) arch=amd64 ;; esac
ver=9.9.9
tag="v$ver"
host="watchdeck_${ver}_${os}_${arch}.tar.gz"

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

# The fake release: four archives, each holding a watchdeck sh script that
# prints the version (the real binary is never built or downloaded here), a
# .sbom.json beside each, checksums.txt in goreleaser's format over all
# eight, and a bundle file the cosign stub accepts. $tmp/rel is the pristine
# copy; the cases that tamper work on their own copy.
build_release() { # build_release <dir> <printed-version>
	mkdir -p "$1"
	: >"$1/checksums.txt"
	for o in darwin linux; do
		for a in arm64 amd64; do
			name="watchdeck_${ver}_${o}_${a}.tar.gz"
			stage="$tmp/stage-$o-$a"
			rm -rf "$stage"
			mkdir -p "$stage"
			printf '#!/bin/sh\necho "watchdeck %s"\n' "$2" >"$stage/watchdeck"
			chmod 0755 "$stage/watchdeck"
			echo "fake license" >"$stage/LICENSE"
			tar -czf "$1/$name" -C "$stage" watchdeck LICENSE
			printf '{"stub": "not a real sbom", "name": "%s"}\n' "$name" >"$1/$name.sbom.json"
			echo "$(sha256_of "$1/$name")  $name" >>"$1/checksums.txt"
			echo "$(sha256_of "$1/$name.sbom.json")  $name.sbom.json" >>"$1/checksums.txt"
		done
	done
	printf '{"stub": "not a real bundle"}\n' >"$1/checksums.txt.sigstore.json"
}
build_release "$tmp/rel" "$tag"
[ "$(wc -l <"$tmp/rel/checksums.txt" | tr -d ' ')" = "8" ] || fail "fixture checksums.txt has the wrong line count"

# From here on nothing may see the real home, the real GitHub CLI config or
# any token; TMPDIR is a temp dir of its own so the scripts' cleanup can be
# checked.
export HOME="$tmp/home" XDG_CONFIG_HOME="$tmp/home/.config" XDG_STATE_HOME="$tmp/home/.local/state" \
	XDG_CACHE_HOME="$tmp/home/.cache" CLAUDE_CONFIG_DIR="$tmp/home/.claude" WATCHDECK_ACTIVITY="$tmp/activity.jsonl" \
	GH_CONFIG_DIR="$tmp/home/.config/gh" TMPDIR="$tmp/tmpdir"
mkdir -p "$HOME" "$CLAUDE_CONFIG_DIR" "$GH_CONFIG_DIR" "$TMPDIR"
unset WATCHDECK_VERIFY GH_TOKEN GITHUB_TOKEN GH_HOST GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN || true

# Stubs: sh scripts named exactly gh and cosign, first on PATH. Each appends
# its name and argv to $STUB_LOG, prints $STUB_ERR to stderr when set, and
# exits per $STUB_RC; $STUB_GH_RC and $STUB_COSIGN_RC override it per tool so
# one case can make one tool fail while the other passes. `gh auth status`
# exits per $STUB_AUTH_RC, `gh release view` prints $STUB_DRAFT (false by
# default) and `gh release download` copies the files of $STUB_REL into the
# --dir argument, exiting per $STUB_DL_RC. $tmp/stubs-gh holds gh alone and
# $tmp/minbin only the tools verify-release.sh needs before its cosign
# check, for the case without cosign (a trimmed PATH alone would still find
# a real cosign installed later on PATH and run it against the fake bundle).
export STUB_LOG="$tmp/stub.log"
mkdir "$tmp/stubs" "$tmp/stubs-gh" "$tmp/minbin"
cat >"$tmp/stubs/gh" <<'STUB'
#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >>"$STUB_LOG"
[ -z "${STUB_ERR:-}" ] || echo "$STUB_ERR" >&2
case "${1:-} ${2:-}" in
"auth status") exit "${STUB_AUTH_RC:-0}" ;;
"release view") echo "${STUB_DRAFT:-false}"; exit 0 ;;
"release download")
	dir=""
	while [ $# -gt 0 ]; do
		case "$1" in --dir) dir="$2"; shift 2 ;; *) shift ;; esac
	done
	[ -n "$dir" ] || { echo "stub: no --dir" >&2; exit 2; }
	[ "${STUB_DL_RC:-0}" -eq 0 ] || exit "${STUB_DL_RC}"
	cp "${STUB_REL:?}"/* "$dir"/
	exit 0
	;;
esac
exit "${STUB_GH_RC:-${STUB_RC:-0}}"
STUB
cat >"$tmp/stubs/cosign" <<'STUB'
#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >>"$STUB_LOG"
[ -z "${STUB_ERR:-}" ] || echo "$STUB_ERR" >&2
exit "${STUB_COSIGN_RC:-${STUB_RC:-0}}"
STUB
chmod 0755 "$tmp/stubs/gh" "$tmp/stubs/cosign"
cp -p "$tmp/stubs/gh" "$tmp/stubs-gh/gh"
for t in sh uname grep tar sha256sum shasum; do
	if command -v "$t" >/dev/null 2>&1; then ln -s "$(command -v "$t")" "$tmp/minbin/$t"; fi
done
export PATH="$tmp/stubs:$PATH"
[ "$(command -v gh)" = "$tmp/stubs/gh" ] || fail "the gh stub is not first on PATH"
[ "$(command -v cosign)" = "$tmp/stubs/cosign" ] || fail "the cosign stub is not first on PATH"
[ "$(PATH="$tmp/stubs-gh:$tmp/minbin" command -v cosign || true)" = "" ] || fail "cosign is reachable from the minimal PATH"
[ "$(PATH="$tmp/stubs-gh:$tmp/minbin" command -v gh)" = "$tmp/stubs-gh/gh" ] || fail "the gh stub is not on the minimal PATH"

cosign_line="cosign verify-blob --certificate-identity https://github.com/Panda-Taps-LLC/watchdeck/.github/workflows/release.yml@refs/tags/$tag --certificate-oidc-issuer https://token.actions.githubusercontent.com --bundle .*/checksums.txt.sigstore.json .*/checksums.txt\$"
gh_line="gh attestation verify .*/watchdeck_${ver}_%s.tar.gz --repo Panda-Taps-LLC/watchdeck --signer-workflow Panda-Taps-LLC/watchdeck/.github/workflows/release.yml\$"

# tmpdir_clean: the scripts' own mktemp dirs are gone after every run.
tmpdir_clean() {
	[ -z "$(ls -A "$TMPDIR")" ] || { ls -A "$TMPDIR"; fail "$1: left files under TMPDIR"; }
}
# dir_digest <dir>: a digest of every file's name and content, to show a
# --from directory is untouched.
dir_digest() {
	(cd "$1" && for f in *; do printf '%s %s\n' "$f" "$(sha256_of "$f")"; done)
}

# 1. --from a good release: every check passes, one ok line each; the cosign
# and gh lines are the SECURITY.md blocks; the --from dir is untouched
before="$(dir_digest "$tmp/rel")"
rm -f "$STUB_LOG"
sh "$verify" "$tag" --from "$tmp/rel" >"$tmp/out1" 2>&1 || { cat "$tmp/out1"; fail "verify --from failed"; }
grep -q "^ok: read 10 files from " "$tmp/out1" || { cat "$tmp/out1"; fail "no read line"; }
grep -q "^ok: cosign bundle verifies checksums.txt (identity release.yml@refs/tags/$tag)$" "$tmp/out1" || { cat "$tmp/out1"; fail "no cosign ok line"; }
for p in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do
	grep -q "^ok: attestation verifies watchdeck_${ver}_${p}.tar.gz (signer release.yml)$" "$tmp/out1" || { cat "$tmp/out1"; fail "no attestation ok line for $p"; }
	grep -q "^ok: sha256 watchdeck_${ver}_${p}.tar.gz$" "$tmp/out1" || { cat "$tmp/out1"; fail "no sha256 line for $p"; }
	grep -q "^ok: sha256 watchdeck_${ver}_${p}.tar.gz.sbom.json$" "$tmp/out1" || { cat "$tmp/out1"; fail "no sha256 line for the $p sbom"; }
	grep -q "^ok: unpacked watchdeck_${ver}_${p}.tar.gz (watchdeck binary present)$" "$tmp/out1" || { cat "$tmp/out1"; fail "no unpack line for $p"; }
	# shellcheck disable=SC2059 # gh_line is a pattern with one %s
	grep -q "^$(printf "$gh_line" "$p")" "$STUB_LOG" || { cat "$STUB_LOG"; fail "gh attestation verify line wrong for $p"; }
done
grep -q "^ok: watchdeck version from $host prints $ver$" "$tmp/out1" || { cat "$tmp/out1"; fail "no version line"; }
grep -q "^PASS: $tag verified (10 files, cosign bundle, 4 attestations, 8 checksums)$" "$tmp/out1" || { cat "$tmp/out1"; fail "no PASS line"; }
[ "$(grep -c '^ok: ' "$tmp/out1")" = "19" ] || { cat "$tmp/out1"; fail "expected 19 ok lines"; }
grep -q "^$cosign_line" "$STUB_LOG" || { cat "$STUB_LOG"; fail "cosign verify-blob line wrong"; }
grep -q "^gh auth status$" "$STUB_LOG" || fail "gh auth status not checked"
[ "$(grep -c '^gh attestation verify ' "$STUB_LOG")" = "4" ] || { cat "$STUB_LOG"; fail "expected 4 attestation calls"; }
if grep -q "^gh release" "$STUB_LOG"; then fail "--from reached gh release"; fi
[ "$(dir_digest "$tmp/rel")" = "$before" ] || fail "--from directory changed"
tmpdir_clean "case 1"
echo "ok: both verify blocks pass on a good release (--from)"

# 2. the download path through the gh stub: the release is looked up, then
# every file downloaded by name into the script's temp dir
rm -f "$STUB_LOG"
STUB_REL="$tmp/rel" sh "$verify" "$tag" >"$tmp/out2" 2>&1 || { cat "$tmp/out2"; fail "verify with download failed"; }
grep -q "^ok: release $tag is published$" "$tmp/out2" || { cat "$tmp/out2"; fail "no published line"; }
grep -q "^ok: downloaded 10 files of $tag$" "$tmp/out2" || { cat "$tmp/out2"; fail "no downloaded line"; }
grep -q "^PASS: " "$tmp/out2" || { cat "$tmp/out2"; fail "no PASS after download"; }
grep -q "^gh release view $tag --repo Panda-Taps-LLC/watchdeck --json isDraft --jq .isDraft$" "$STUB_LOG" || { cat "$STUB_LOG"; fail "release view line wrong"; }
dl="$(grep '^gh release download ' "$STUB_LOG" || true)"
[ -n "$dl" ] || { cat "$STUB_LOG"; fail "no release download call"; }
case "$dl" in
"gh release download $tag --repo Panda-Taps-LLC/watchdeck --dir $TMPDIR/watchdeck-verify."*) ;;
*) echo "$dl"; fail "release download line wrong" ;;
esac
for f in checksums.txt checksums.txt.sigstore.json "$host" "$host.sbom.json"; do
	case "$dl" in *" --pattern $f"*) ;; *) echo "$dl"; fail "download does not name $f" ;; esac
done
[ "$(printf '%s\n' "$dl" | grep -o -- '--pattern ' | wc -l | tr -d ' ')" = "10" ] || fail "expected 10 --pattern flags"
tmpdir_clean "case 2"
echo "ok: downloads every file by name through gh release download"

# 3. a draft is refused without --draft and accepted with it; a failed
# download refuses with the reason
rm -f "$STUB_LOG"
if STUB_REL="$tmp/rel" STUB_DRAFT=true sh "$verify" "$tag" >"$tmp/out3" 2>&1; then fail "draft accepted without --draft"; fi
grep -q "FAIL: $tag is a draft; pass --draft" "$tmp/out3" || { cat "$tmp/out3"; fail "no draft refusal"; }
if grep -q "^gh release download" "$STUB_LOG"; then fail "downloaded a draft without --draft"; fi
STUB_REL="$tmp/rel" STUB_DRAFT=true sh "$verify" "$tag" --draft >"$tmp/out3b" 2>&1 || { cat "$tmp/out3b"; fail "--draft failed"; }
grep -q "^ok: release $tag is a draft (--draft)$" "$tmp/out3b" || { cat "$tmp/out3b"; fail "no draft ok line"; }
grep -q "^PASS: " "$tmp/out3b" || fail "no PASS for the draft"
if STUB_REL="$tmp/rel" STUB_DL_RC=1 STUB_ERR="$(printf '\nHTTP 404: Not Found')" sh "$verify" "$tag" >"$tmp/out3c" 2>&1; then fail "failed download accepted"; fi
grep -q "FAIL: could not download the release files of $tag: HTTP 404: Not Found" "$tmp/out3c" || { cat "$tmp/out3c"; fail "no download failure reason"; }
tmpdir_clean "case 3"
echo "ok: a draft needs --draft; a failed download refuses"

# 4. a failing cosign refuses, names the reason (first non-blank stderr
# line), and no attestation is checked after it
rm -f "$STUB_LOG"
if STUB_COSIGN_RC=1 STUB_ERR="$(printf '\nError: none of the expected identities matched')" sh "$verify" "$tag" --from "$tmp/rel" >"$tmp/out4" 2>&1; then fail "failing cosign accepted"; fi
grep -q "FAIL: cosign bundle does not verify checksums.txt for $tag: Error: none of the expected identities matched" "$tmp/out4" || { cat "$tmp/out4"; fail "no cosign failure message"; }
if grep -q "^ok: cosign" "$tmp/out4"; then fail "cosign ok printed on failure"; fi
grep -q "^cosign verify-blob" "$STUB_LOG" || fail "cosign not run"
if grep -q "^gh attestation" "$STUB_LOG"; then fail "attestation checked after cosign failed"; fi
if grep -q "^ok: sha256" "$tmp/out4"; then fail "checksums checked after cosign failed"; fi
tmpdir_clean "case 4"
echo "ok: a failing cosign refuses"

# 5. a failing attestation refuses on the first archive, after cosign passed
rm -f "$STUB_LOG"
if STUB_GH_RC=1 STUB_ERR="stub: no attestations found" sh "$verify" "$tag" --from "$tmp/rel" >"$tmp/out5" 2>&1; then fail "failing attestation accepted"; fi
grep -q "^ok: cosign bundle verifies checksums.txt" "$tmp/out5" || { cat "$tmp/out5"; fail "cosign did not pass before the attestation"; }
grep -q "FAIL: attestation does not verify watchdeck_${ver}_darwin_arm64.tar.gz: stub: no attestations found" "$tmp/out5" || { cat "$tmp/out5"; fail "no attestation failure message"; }
[ "$(grep -c '^gh attestation verify ' "$STUB_LOG")" = "1" ] || { cat "$STUB_LOG"; fail "attestation went on after the first failure"; }
if grep -q "^ok: sha256" "$tmp/out5"; then fail "checksums checked after the attestation failed"; fi
tmpdir_clean "case 5"
echo "ok: a failing attestation refuses"

# 6. a tampered checksum is refused after both verifications passed (verify
# first, then sha256); the message names the file
build_release "$tmp/rel6" "$tag"
sed "s/^[0-9a-f]\{64\}  \(watchdeck_${ver}_linux_amd64.tar.gz\)$/0000000000000000000000000000000000000000000000000000000000000000  \1/" "$tmp/rel6/checksums.txt" >"$tmp/rel6/c.tmp"
mv "$tmp/rel6/c.tmp" "$tmp/rel6/checksums.txt"
grep -q "^0000" "$tmp/rel6/checksums.txt" || fail "fixture: tamper did not apply"
if sh "$verify" "$tag" --from "$tmp/rel6" >"$tmp/out6" 2>&1; then fail "tampered checksum accepted"; fi
grep -q "^ok: cosign bundle verifies" "$tmp/out6" || { cat "$tmp/out6"; fail "verify did not run before the checksum"; }
[ "$(grep -c '^ok: attestation verifies' "$tmp/out6")" = "4" ] || { cat "$tmp/out6"; fail "attestations did not all pass before the checksum"; }
grep -q "FAIL: checksum mismatch for watchdeck_${ver}_linux_amd64.tar.gz (expected 0000" "$tmp/out6" || { cat "$tmp/out6"; fail "no mismatch message"; }
if grep -q "^ok: unpacked" "$tmp/out6"; then fail "unpacked after a mismatch"; fi
tmpdir_clean "case 6"
# a tampered archive (the listed digest is right, the file is not)
build_release "$tmp/rel6b" "$tag"
echo "extra" >>"$tmp/rel6b/$host"
if sh "$verify" "$tag" --from "$tmp/rel6b" >"$tmp/out6b" 2>&1; then fail "tampered archive accepted"; fi
grep -q "FAIL: checksum mismatch for $host" "$tmp/out6b" || { cat "$tmp/out6b"; fail "no mismatch for the tampered archive"; }
echo "ok: a tampered checksum is refused after a passing verify"

# 7. a missing file refuses before any tool runs (the sbom, then the
# bundle as an unsigned draft on the download path)
build_release "$tmp/rel7" "$tag"
rm "$tmp/rel7/watchdeck_${ver}_linux_arm64.tar.gz.sbom.json"
rm -f "$STUB_LOG"
if sh "$verify" "$tag" --from "$tmp/rel7" >"$tmp/out7" 2>&1; then fail "missing sbom accepted"; fi
grep -q "FAIL: missing from $tmp/rel7: watchdeck_${ver}_linux_arm64.tar.gz.sbom.json" "$tmp/out7" || { cat "$tmp/out7"; fail "no missing-file message"; }
if grep -q "^cosign\|^gh attestation" "$STUB_LOG"; then fail "a tool ran with a file missing"; fi
build_release "$tmp/rel7b" "$tag"
rm "$tmp/rel7b/checksums.txt.sigstore.json"
rm -f "$STUB_LOG"
if STUB_REL="$tmp/rel7b" sh "$verify" "$tag" >"$tmp/out7b" 2>&1; then fail "release without a bundle accepted"; fi
grep -q "FAIL: missing from the release: checksums.txt.sigstore.json (an unsigned draft" "$tmp/out7b" || { cat "$tmp/out7b"; fail "no unsigned-draft message"; }
if grep -q "^cosign" "$STUB_LOG"; then fail "cosign ran without a bundle"; fi
tmpdir_clean "case 7"
echo "ok: a missing file refuses before any tool runs"

# 8. checksums.txt that lists an unexpected file, or lacks a listed one,
# refuses; a malformed digest, a nameless line and a duplicate line with a
# wrong digest refuse
build_release "$tmp/rel8" "$tag"
echo "$(sha256_of "$tmp/rel8/checksums.txt.sigstore.json")  watchdeck_${ver}_windows_amd64.zip" >>"$tmp/rel8/checksums.txt"
if sh "$verify" "$tag" --from "$tmp/rel8" >"$tmp/out8" 2>&1; then fail "unexpected listed file accepted"; fi
grep -q "FAIL: checksums.txt lists watchdeck_${ver}_windows_amd64.zip, which this script does not expect" "$tmp/out8" || { cat "$tmp/out8"; fail "no unexpected-file message"; }
build_release "$tmp/rel8b" "$tag"
grep -v "watchdeck_${ver}_darwin_amd64.tar.gz.sbom.json" "$tmp/rel8b/checksums.txt" >"$tmp/rel8b/c.tmp"
mv "$tmp/rel8b/c.tmp" "$tmp/rel8b/checksums.txt"
if sh "$verify" "$tag" --from "$tmp/rel8b" >"$tmp/out8b" 2>&1; then fail "unlisted sbom accepted"; fi
grep -q "FAIL: watchdeck_${ver}_darwin_amd64.tar.gz.sbom.json is not listed in checksums.txt" "$tmp/out8b" || { cat "$tmp/out8b"; fail "no not-listed message"; }
build_release "$tmp/rel8c" "$tag"
sed "s/^[0-9a-f]\{64\}  \($host\)$/abc  \1/" "$tmp/rel8c/checksums.txt" >"$tmp/rel8c/c.tmp"
mv "$tmp/rel8c/c.tmp" "$tmp/rel8c/checksums.txt"
if sh "$verify" "$tag" --from "$tmp/rel8c" >"$tmp/out8c" 2>&1; then fail "malformed digest accepted"; fi
grep -q "FAIL: checksums.txt has a malformed entry for $host" "$tmp/out8c" || { cat "$tmp/out8c"; fail "no malformed-entry message"; }
# a line with a digest and no name
build_release "$tmp/rel8d" "$tag"
echo "0000000000000000000000000000000000000000000000000000000000000000" >>"$tmp/rel8d/checksums.txt"
if sh "$verify" "$tag" --from "$tmp/rel8d" >"$tmp/out8d" 2>&1; then fail "nameless digest line accepted"; fi
grep -q "FAIL: checksums.txt has a line with no file name: 0000" "$tmp/out8d" || { cat "$tmp/out8d"; fail "no nameless-line message"; }
# a duplicate line for a listed file with another digest (the first line is
# right, the second is not): every line is checked, not the first match
build_release "$tmp/rel8e" "$tag"
echo "1111111111111111111111111111111111111111111111111111111111111111  $host" >>"$tmp/rel8e/checksums.txt"
if sh "$verify" "$tag" --from "$tmp/rel8e" >"$tmp/out8e" 2>&1; then fail "duplicate line with a wrong digest accepted"; fi
grep -q "FAIL: checksum mismatch for $host (expected 1111" "$tmp/out8e" || { cat "$tmp/out8e"; fail "no mismatch for the duplicate line"; }
tmpdir_clean "case 8"
echo "ok: checksums.txt must list exactly the release files with well-formed digests"

# 9. the host archive's watchdeck must print the version; an archive without
# a watchdeck binary refuses
build_release "$tmp/rel9" "v0.0.0-wrong"
if sh "$verify" "$tag" --from "$tmp/rel9" >"$tmp/out9" 2>&1; then fail "wrong version accepted"; fi
grep -q "FAIL: watchdeck version from $host printed 'watchdeck v0.0.0-wrong', expected it to name $ver" "$tmp/out9" || { cat "$tmp/out9"; fail "no wrong-version message"; }
[ "$(grep -c '^ok: unpacked' "$tmp/out9")" = "4" ] || { cat "$tmp/out9"; fail "archives not all unpacked before the version check"; }
build_release "$tmp/rel9b" "$tag"
mkdir "$tmp/stage-empty"
echo "fake license" >"$tmp/stage-empty/LICENSE"
tar -czf "$tmp/rel9b/$host" -C "$tmp/stage-empty" LICENSE
sed "s/^[0-9a-f]\{64\}  \($host\)$/$(sha256_of "$tmp/rel9b/$host")  \1/" "$tmp/rel9b/checksums.txt" >"$tmp/rel9b/c.tmp"
mv "$tmp/rel9b/c.tmp" "$tmp/rel9b/checksums.txt"
if sh "$verify" "$tag" --from "$tmp/rel9b" >"$tmp/out9b" 2>&1; then fail "archive without a binary accepted"; fi
grep -q "FAIL: no watchdeck binary at the top of $host" "$tmp/out9b" || { cat "$tmp/out9b"; fail "no missing-binary message"; }
tmpdir_clean "case 9"
echo "ok: the host archive must run and print the version"

# 10. tool preconditions: gh signed out, cosign absent, a bad tag; each
# refuses before anything is read or downloaded
rm -f "$STUB_LOG"
if STUB_AUTH_RC=1 sh "$verify" "$tag" --from "$tmp/rel" >"$tmp/out10" 2>&1; then fail "gh signed out accepted"; fi
grep -q "FAIL: the GitHub CLI is not signed in (gh auth login)" "$tmp/out10" || { cat "$tmp/out10"; fail "no signed-out message"; }
if grep -q "^cosign\|^gh attestation\|^gh release" "$STUB_LOG"; then fail "a check ran while gh was signed out"; fi
if PATH="$tmp/stubs-gh:$tmp/minbin" sh "$verify" "$tag" --from "$tmp/rel" >"$tmp/out10b" 2>&1; then fail "missing cosign accepted"; fi
grep -q "FAIL: need cosign 3.x" "$tmp/out10b" || { cat "$tmp/out10b"; fail "no missing-cosign message"; }
for v in 9.9.9 'v1/../../../x' 'v1.2.3/..' 'v1.2' 'v1.2.3 x'; do
	if sh "$verify" "$v" --from "$tmp/rel" >"$tmp/out10c" 2>&1; then fail "bad tag accepted: $v"; fi
	grep -q "FAIL: tag must look like v0.1.0" "$tmp/out10c" || { cat "$tmp/out10c"; fail "no tag error for: $v"; }
done
if sh "$verify" >"$tmp/out10d" 2>&1; then fail "no tag accepted"; fi
grep -q "FAIL: a tag is required" "$tmp/out10d" || { cat "$tmp/out10d"; fail "no tag-required message"; }
if sh "$verify" "$tag" --from "$tmp/does-not-exist" >"$tmp/out10e" 2>&1; then fail "missing --from dir accepted"; fi
grep -q "FAIL: --from $tmp/does-not-exist is not a directory" "$tmp/out10e" || { cat "$tmp/out10e"; fail "no --from dir message"; }
tmpdir_clean "case 10"
echo "ok: gh signed out, no cosign and a bad tag refuse before any check"

# 11. the formula fills VERSION and all four digests from checksums.txt; the
# template's header is dropped; --out writes the same text
sh "$formula" "$tag" "$tmp/rel/checksums.txt" >"$tmp/formula.rb" 2>"$tmp/err11" || { cat "$tmp/err11"; fail "tap-formula failed"; }
if grep -q "{{" "$tmp/formula.rb"; then cat "$tmp/formula.rb"; fail "a placeholder is left in the formula"; fi
grep -q "^  version \"$ver\"$" "$tmp/formula.rb" || { cat "$tmp/formula.rb"; fail "version line wrong"; }
grep -q "^class Watchdeck < Formula$" "$tmp/formula.rb" || fail "no class line"
[ "$(sed -n 2p "$tmp/formula.rb")" = "class Watchdeck < Formula" ] || { head -n 3 "$tmp/formula.rb"; fail "the template header was not dropped"; }
grep -q "^# Filled by scripts/tap-formula.sh from the verified checksums.txt of $tag. Do not edit by hand.$" "$tmp/formula.rb" || fail "no generated-by line"
for p in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do
	want="$(awk -v f="watchdeck_${ver}_${p}.tar.gz" '$2 == f { print $1 }' "$tmp/rel/checksums.txt")"
	grep -q "^      url \"https://github.com/Panda-Taps-LLC/watchdeck/releases/download/$tag/watchdeck_${ver}_${p}.tar.gz\"$" "$tmp/formula.rb" || { cat "$tmp/formula.rb"; fail "url line wrong for $p"; }
	grep -A1 "watchdeck_${ver}_${p}.tar.gz\"$" "$tmp/formula.rb" | grep -q "^      sha256 \"$want\"$" || { cat "$tmp/formula.rb"; fail "sha256 line wrong for $p"; }
done
[ "$(grep -c '^      sha256 "' "$tmp/formula.rb")" = "4" ] || fail "expected four sha256 lines"
grep -q '^  desc "Every Claude Code session as a live map; turn a denial into a rule in one click"$' "$tmp/formula.rb" || fail "desc line missing"
mkdir "$tmp/Formula"
sh "$formula" "$tag" "$tmp/rel/checksums.txt" --out "$tmp/Formula/watchdeck.rb" >"$tmp/out11" 2>"$tmp/err11b" || { cat "$tmp/err11b"; fail "tap-formula --out failed"; }
[ ! -s "$tmp/out11" ] || fail "--out still printed to stdout"
grep -q "^wrote $tmp/Formula/watchdeck.rb ($tag)$" "$tmp/err11b" || { cat "$tmp/err11b"; fail "no wrote line"; }
cmp -s "$tmp/formula.rb" "$tmp/Formula/watchdeck.rb" || fail "--out differs from stdout"
# the digest with a leading * (sha256sum --binary style) is read too
sed 's/  \(watchdeck_\)/ *\1/' "$tmp/rel/checksums.txt" >"$tmp/checksums-star.txt"
sh "$formula" "$tag" "$tmp/checksums-star.txt" >"$tmp/formula-star.rb" 2>/dev/null || fail "tap-formula failed on *name lines"
cmp -s "$tmp/formula.rb" "$tmp/formula-star.rb" || fail "*name lines give a different formula"
echo "ok: the formula fills the version and all four digests"

# 12. a missing line, a malformed digest, a malformed tag and a missing
# checksums file refuse by name; --out writes nothing on failure
grep -v "watchdeck_${ver}_linux_arm64.tar.gz$" "$tmp/rel/checksums.txt" >"$tmp/checksums-missing.txt"
if sh "$formula" "$tag" "$tmp/checksums-missing.txt" --out "$tmp/Formula/bad.rb" >"$tmp/out12" 2>&1; then fail "missing line accepted"; fi
grep -q "tap-formula.sh: $tmp/checksums-missing.txt has no line for watchdeck_${ver}_linux_arm64.tar.gz" "$tmp/out12" || { cat "$tmp/out12"; fail "no missing-line message"; }
[ ! -e "$tmp/Formula/bad.rb" ] || fail "--out written despite a missing line"
sed "s/^[0-9a-f]\{64\}  \(watchdeck_${ver}_darwin_amd64.tar.gz\)$/0123456789abcdefXYZ  \1/" "$tmp/rel/checksums.txt" >"$tmp/checksums-bad.txt"
if sh "$formula" "$tag" "$tmp/checksums-bad.txt" >"$tmp/out12b" 2>&1; then fail "malformed digest accepted"; fi
grep -q "has a malformed digest for watchdeck_${ver}_darwin_amd64.tar.gz (want 64 lowercase hex characters, got: 0123456789abcdefXYZ)" "$tmp/out12b" || { cat "$tmp/out12b"; fail "no malformed-digest message"; }
# uppercase hex is refused too: Homebrew wants lowercase
sed "s/^\([0-9a-f]\{64\}\)  \(watchdeck_${ver}_darwin_amd64.tar.gz\)$/$(awk -v f="watchdeck_${ver}_darwin_amd64.tar.gz" '$2 == f { print toupper($1) }' "$tmp/rel/checksums.txt")  \2/" "$tmp/rel/checksums.txt" >"$tmp/checksums-upper.txt"
if sh "$formula" "$tag" "$tmp/checksums-upper.txt" >"$tmp/out12c" 2>&1; then fail "uppercase digest accepted"; fi
grep -q "has a malformed digest for watchdeck_${ver}_darwin_amd64.tar.gz" "$tmp/out12c" || { cat "$tmp/out12c"; fail "no uppercase refusal"; }
for v in 9.9.9 'v1/../../../x' 'v1.2' 'v1.2.3 x'; do
	if sh "$formula" "$v" "$tmp/rel/checksums.txt" >"$tmp/out12d" 2>&1; then fail "bad tag accepted: $v"; fi
	grep -q "tap-formula.sh: tag must look like v0.1.0" "$tmp/out12d" || { cat "$tmp/out12d"; fail "no tag error for: $v"; }
done
if sh "$formula" "$tag" "$tmp/no-such-checksums.txt" >"$tmp/out12e" 2>&1; then fail "missing checksums file accepted"; fi
grep -q "tap-formula.sh: $tmp/no-such-checksums.txt is not a file" "$tmp/out12e" || { cat "$tmp/out12e"; fail "no missing-file message"; }
if sh "$formula" "$tag" >"$tmp/out12f" 2>&1; then fail "missing checksums argument accepted"; fi
grep -q "a tag and a checksums.txt are required" "$tmp/out12f" || { cat "$tmp/out12f"; fail "no usage error"; }
# a tag with a pre-release suffix is accepted and spelled through
printf '%s\n' "$(sed "s/_${ver}_/_${ver}-rc.1_/" "$tmp/rel/checksums.txt")" >"$tmp/checksums-rc.txt"
sh "$formula" "$tag-rc.1" "$tmp/checksums-rc.txt" >"$tmp/formula-rc.rb" 2>/dev/null || fail "pre-release tag refused"
grep -q "^  version \"$ver-rc.1\"$" "$tmp/formula-rc.rb" || { cat "$tmp/formula-rc.rb"; fail "pre-release version wrong"; }
grep -q "/download/$tag-rc.1/watchdeck_$ver-rc.1_darwin_arm64.tar.gz\"$" "$tmp/formula-rc.rb" || { cat "$tmp/formula-rc.rb"; fail "pre-release url wrong"; }
echo "ok: a missing line, a malformed digest and a malformed tag refuse"

# 13. the filled formula is Ruby that parses (ruby -c), when ruby is present
if command -v ruby >/dev/null 2>&1; then
	ruby -c "$tmp/formula.rb" >"$tmp/out13" 2>&1 || { cat "$tmp/out13"; fail "ruby -c rejects the formula"; }
	grep -q "Syntax OK" "$tmp/out13" || { cat "$tmp/out13"; fail "ruby -c did not say Syntax OK"; }
	echo "ok: the filled formula passes ruby -c"
else
	echo "skip: ruby -c (ruby is not on PATH)"
fi

tmpdir_clean "end"
echo "PASS ($(( $(date +%s) - started )) s)"
