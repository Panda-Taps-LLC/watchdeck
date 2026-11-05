#!/bin/sh
# Verifies a watchdeck release end to end: CONTRIBUTING "Releasing" steps 7
# and 8 as one command, run by the owner before publishing a draft and again
# on the published assets.
#
# Usage: verify-release.sh <tag> [--draft] [--from DIR]
#
#   <tag>     the release tag, vX.Y.Z
#   --draft   the release may still be a draft (the owner's review before
#             publishing); without it a draft is refused
#   --from    read the release files from a local directory instead of
#             downloading them (tests)
#
# What it checks, one line per check, stopping at the first failure (exit 1):
#   1. every file of the release is there: the four archives
#      (watchdeck_<version>_<os>_<arch>.tar.gz for darwin/linux x arm64/amd64),
#      their four .sbom.json, checksums.txt and checksums.txt.sigstore.json
#      (an archive without the bundle is an unsigned draft);
#   2. the cosign block from SECURITY.md "Verify a release": the keyless
#      bundle on checksums.txt, identity this repository's release workflow
#      at the tag;
#   3. the gh block from SECURITY.md on every archive: the build-provenance
#      attestation, signer workflow this repository's release workflow;
#   4. the sha256 of every file checksums.txt lists, and that checksums.txt
#      lists exactly the files above (nothing listed goes unverified);
#   5. every archive unpacks and holds a watchdeck binary; the host's own
#      archive runs `watchdeck version` and prints the version.
#
# Needs: the GitHub CLI signed in (gh auth login) and cosign 3.x; sha256sum
# or shasum; tar. Everything happens in one mktemp directory, removed on
# exit; nothing is installed and nothing is written anywhere else. Every
# tool reads /dev/null. The identity strings are the ones in SECURITY.md
# and scripts/install.sh --verify; do not edit them here alone.
#
# The whole script is inside main(), called on the last line.

REPO="Panda-Taps-LLC/watchdeck"

die() { echo "verify-release.sh: FAIL: $*" >&2; exit 1; }

usage() {
	cat <<'USAGE'
Usage: verify-release.sh <tag> [--draft] [--from DIR]
  <tag>     release tag, vX.Y.Z
  --draft   allow a draft release (the owner's review before publishing)
  --from    read the release files from a local directory instead of
            downloading them with the GitHub CLI
Checks the files, the cosign bundle on checksums.txt, the attestation on
every archive, every sha256, and `watchdeck version` from the host's archive.
Exit 1 on the first failure. Writes nothing outside a temp dir removed on exit.
USAGE
}

# valid_version: v<d>.<d>.<d> optionally followed by -[0-9A-Za-z.-]*; no slash,
# no "..", no whitespace (the same rule as scripts/install.sh).
valid_version() {
	case "$1" in
	*..* | */* | *[[:space:]]*) return 1 ;;
	esac
	printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
}

# first_line <file>: the first non-blank line of a tool's stderr (gh prints a
# blank line before its Error: line).
first_line() {
	sed -n '/[^[:space:]]/{p;q;}' "$1"
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print $1 }'
	else
		shasum -a 256 "$1" | awk '{ print $1 }'
	fi
}

main() {
	set -eu
	tag=""
	draft=""
	from=""

	while [ $# -gt 0 ]; do
		case "$1" in
		--draft) draft=1; shift ;;
		--from) [ $# -ge 2 ] || die "--from needs a value"; from="$2"; shift 2 ;;
		-h | --help) usage; exit 0 ;;
		-*) die "unknown argument: $1" ;;
		*)
			[ -z "$tag" ] || die "one tag only, got: $tag and $1"
			tag="$1"
			shift
			;;
		esac
	done
	[ -n "$tag" ] || { usage >&2; die "a tag is required"; }
	valid_version "$tag" || die "tag must look like v0.1.0 (letters, digits, dot, dash only), got: $tag"
	version="${tag#v}"

	case "$(uname -s)" in
	Darwin) host_os=darwin ;;
	Linux) host_os=linux ;;
	*) die "unsupported OS: $(uname -s) (darwin and linux only)" ;;
	esac
	case "$(uname -m)" in
	arm64 | aarch64) host_arch=arm64 ;;
	x86_64 | amd64) host_arch=amd64 ;;
	*) die "unsupported architecture: $(uname -m) (arm64 and amd64 only)" ;;
	esac

	command -v tar >/dev/null 2>&1 || die "need tar"
	command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || die "need sha256sum or shasum"
	command -v cosign >/dev/null 2>&1 || die "need cosign 3.x (brew install cosign) for the bundle check"
	command -v gh >/dev/null 2>&1 || die "need the GitHub CLI (gh) for the attestation check"
	gh auth status </dev/null >/dev/null 2>&1 || die "the GitHub CLI is not signed in (gh auth login); gh attestation verify needs it"

	# The release's files. Four archives and their SBOMs are listed in
	# checksums.txt; the bundle signs checksums.txt.
	archives=""
	listed=""
	for os in darwin linux; do
		for arch in arm64 amd64; do
			a="watchdeck_${version}_${os}_${arch}.tar.gz"
			archives="$archives $a"
			listed="$listed $a $a.sbom.json"
		done
	done
	all="$listed checksums.txt checksums.txt.sigstore.json"

	tmp="$(mktemp -d "${TMPDIR:-/tmp}/watchdeck-verify.XXXXXX")"
	trap 'rm -rf "$tmp"' EXIT
	trap 'exit 130' INT TERM
	rel="$tmp/rel"
	mkdir "$rel" "$tmp/x"

	if [ -n "$from" ]; then
		[ -d "$from" ] || die "--from $from is not a directory"
		for f in $all; do
			[ -e "$from/$f" ] || die "missing from $from: $f"
			cp "$from/$f" "$rel/$f"
		done
		echo "ok: read $(echo $all | wc -w | tr -d ' ') files from $from"
	else
		rc=0
		is_draft="$(gh release view "$tag" --repo "$REPO" --json isDraft --jq .isDraft </dev/null 2>"$tmp/gh.err")" || rc=$?
		if [ "$rc" -ne 0 ]; then
			reason="$(first_line "$tmp/gh.err")"
			[ -n "$reason" ] || reason="exit status $rc"
			die "no release $tag in $REPO: $reason"
		fi
		case "$is_draft" in
		true)
			[ -n "$draft" ] || die "$tag is a draft; pass --draft to review it before publishing"
			echo "ok: release $tag is a draft (--draft)"
			;;
		false) echo "ok: release $tag is published" ;;
		*) die "could not tell whether $tag is a draft (gh said: $is_draft)" ;;
		esac
		patterns=""
		for f in $all; do
			patterns="$patterns --pattern $f"
		done
		rc=0
		# shellcheck disable=SC2086 # $patterns is a list of --pattern <name> pairs
		gh release download "$tag" --repo "$REPO" --dir "$rel" $patterns </dev/null >/dev/null 2>"$tmp/gh.err" || rc=$?
		if [ "$rc" -ne 0 ]; then
			reason="$(first_line "$tmp/gh.err")"
			[ -n "$reason" ] || reason="exit status $rc"
			die "could not download the release files of $tag: $reason"
		fi
		for f in $all; do
			if [ ! -e "$rel/$f" ]; then
				case "$f" in
				checksums.txt.sigstore.json) die "missing from the release: $f (an unsigned draft: the repository was not public when the tag was pushed)" ;;
				*) die "missing from the release: $f" ;;
				esac
			fi
		done
		echo "ok: downloaded $(echo $all | wc -w | tr -d ' ') files of $tag"
	fi

	# 2. The cosign block from SECURITY.md on checksums.txt.
	rc=0
	cosign verify-blob \
		--certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$tag" \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com \
		--bundle "$rel/checksums.txt.sigstore.json" "$rel/checksums.txt" </dev/null >/dev/null 2>"$tmp/verify.err" || rc=$?
	if [ "$rc" -ne 0 ]; then
		reason="$(first_line "$tmp/verify.err")"
		[ -n "$reason" ] || reason="exit status $rc"
		die "cosign bundle does not verify checksums.txt for $tag: $reason"
	fi
	echo "ok: cosign bundle verifies checksums.txt (identity release.yml@refs/tags/$tag)"

	# 3. The gh block from SECURITY.md on every archive.
	for a in $archives; do
		rc=0
		gh attestation verify "$rel/$a" --repo "$REPO" \
			--signer-workflow "$REPO/.github/workflows/release.yml" \
			</dev/null >/dev/null 2>"$tmp/verify.err" || rc=$?
		if [ "$rc" -ne 0 ]; then
			reason="$(first_line "$tmp/verify.err")"
			[ -n "$reason" ] || reason="exit status $rc"
			die "attestation does not verify $a: $reason"
		fi
		echo "ok: attestation verifies $a (signer release.yml)"
	done

	# 4. sha256 of everything checksums.txt lists, and nothing else is listed.
	while read -r want name; do
		[ -n "$want" ] || continue
		name="${name#\*}"
		case " $listed " in
		*" $name "*) ;;
		*) die "checksums.txt lists $name, which this script does not expect; update its file list" ;;
		esac
	done <"$rel/checksums.txt"
	for f in $listed; do
		want="$(awk -v f="$f" '$2 == f || $2 == "*" f { print $1; exit }' "$rel/checksums.txt")"
		[ -n "$want" ] || die "$f is not listed in checksums.txt"
		printf '%s\n' "$want" | grep -Eq '^[0-9a-fA-F]{64}$' || die "checksums.txt has a malformed entry for $f"
		got="$(sha256_of "$rel/$f")"
		[ "$got" = "$want" ] || die "checksum mismatch for $f (expected $want, got $got)"
		echo "ok: sha256 $f"
	done

	# 5. Every archive unpacks to a watchdeck binary; the host's runs.
	for a in $archives; do
		d="$tmp/x/${a%.tar.gz}"
		mkdir "$d"
		tar -xzf "$rel/$a" -C "$d" 2>"$tmp/tar.err" || die "could not unpack $a: $(first_line "$tmp/tar.err")"
		[ -f "$d/watchdeck" ] || die "no watchdeck binary at the top of $a"
		echo "ok: unpacked $a (watchdeck binary present)"
	done
	host="watchdeck_${version}_${host_os}_${host_arch}.tar.gz"
	bin="$tmp/x/${host%.tar.gz}/watchdeck"
	chmod 0755 "$bin"
	rc=0
	out="$("$bin" version </dev/null 2>&1)" || rc=$?
	[ "$rc" -eq 0 ] || die "watchdeck version from $host exited $rc: $(printf '%s\n' "$out" | head -n 1)"
	case "$out" in
	*"$version"*) ;;
	*) die "watchdeck version from $host printed '$out', expected it to name $version" ;;
	esac
	echo "ok: watchdeck version from $host prints $version"

	echo "PASS: $tag verified ($(echo $all | wc -w | tr -d ' ') files, cosign bundle, $(echo $archives | wc -w | tr -d ' ') attestations, $(echo $listed | wc -w | tr -d ' ') checksums)"
}

main "$@"
