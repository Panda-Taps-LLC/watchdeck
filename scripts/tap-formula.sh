#!/bin/sh
# Fills packaging/homebrew/watchdeck.rb.tmpl for one release: the formula
# the owner commits to Panda-Taps-LLC/homebrew-tap as Formula/watchdeck.rb
# (CONTRIBUTING "Releasing"). It never downloads anything: run
# scripts/verify-release.sh first and pass the checksums.txt it verified.
#
# Usage: tap-formula.sh <tag> <checksums.txt> [--out FILE]
#
#   <tag>           the release tag, vX.Y.Z; VERSION in the formula is the
#                   tag without the leading v
#   <checksums.txt> the release's checksums.txt; the four sha256 values are
#                   read from it by archive file name
#   --out FILE      write the formula there (the parent directory must
#                   exist) instead of printing it to stdout; nothing is
#                   written when any check fails
#
# Refuses (exit 1, naming the reason) when the tag is malformed, an archive
# has no line in checksums.txt, or a digest is not 64 hex characters.
#
# The whole script is inside main(), called on the last line.

die() { echo "tap-formula.sh: $*" >&2; exit 1; }

usage() {
	cat <<'USAGE'
Usage: tap-formula.sh <tag> <checksums.txt> [--out FILE]
  <tag>            release tag, vX.Y.Z (VERSION is the tag without the v)
  <checksums.txt>  the release's verified checksums.txt
  --out FILE       write the formula to FILE instead of stdout
Fills packaging/homebrew/watchdeck.rb.tmpl; downloads nothing.
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

# digest_for <archive> <checksums.txt>: the sha256 listed for the archive,
# or exit 1 with the reason.
digest_for() {
	d="$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1; exit }' "$2")"
	[ -n "$d" ] || die "$2 has no line for $1"
	printf '%s\n' "$d" | grep -Eq '^[0-9a-f]{64}$' || die "$2 has a malformed digest for $1 (want 64 lowercase hex characters, got: $d)"
	printf '%s\n' "$d"
}

main() {
	set -eu
	root="$(cd "$(dirname "$0")/.." && pwd)"
	tmpl="$root/packaging/homebrew/watchdeck.rb.tmpl"
	tag=""
	sums=""
	out=""

	while [ $# -gt 0 ]; do
		case "$1" in
		--out) [ $# -ge 2 ] || die "--out needs a value"; out="$2"; shift 2 ;;
		-h | --help) usage; exit 0 ;;
		-*) die "unknown argument: $1" ;;
		*)
			if [ -z "$tag" ]; then
				tag="$1"
			elif [ -z "$sums" ]; then
				sums="$1"
			else
				die "too many arguments: $1"
			fi
			shift
			;;
		esac
	done
	[ -n "$tag" ] && [ -n "$sums" ] || { usage >&2; die "a tag and a checksums.txt are required"; }
	valid_version "$tag" || die "tag must look like v0.1.0 (letters, digits, dot, dash only), got: $tag"
	version="${tag#v}"
	[ -f "$sums" ] || die "$sums is not a file"
	[ -f "$tmpl" ] || die "template not found: $tmpl"

	darwin_arm64="$(digest_for "watchdeck_${version}_darwin_arm64.tar.gz" "$sums")"
	darwin_amd64="$(digest_for "watchdeck_${version}_darwin_amd64.tar.gz" "$sums")"
	linux_arm64="$(digest_for "watchdeck_${version}_linux_arm64.tar.gz" "$sums")"
	linux_amd64="$(digest_for "watchdeck_${version}_linux_amd64.tar.gz" "$sums")"

	# The template's own header (what it is, not published yet) stays in the
	# repo; the formula starts at the class line, under one line saying
	# where it came from. The values are validated above (letters, digits,
	# dot, dash; hex), so none can carry a sed delimiter, "&" or a backslash.
	grep -q '^class Watchdeck < Formula$' "$tmpl" || die "template has no 'class Watchdeck < Formula' line: $tmpl"
	formula="$(printf '# Filled by scripts/tap-formula.sh from the verified checksums.txt of %s. Do not edit by hand.\n' "$tag"; sed \
		-e '/^class Watchdeck < Formula$/,$!d' \
		-e "s|{{VERSION}}|$version|g" \
		-e "s|{{SHA256_DARWIN_ARM64}}|$darwin_arm64|g" \
		-e "s|{{SHA256_DARWIN_AMD64}}|$darwin_amd64|g" \
		-e "s|{{SHA256_LINUX_ARM64}}|$linux_arm64|g" \
		-e "s|{{SHA256_LINUX_AMD64}}|$linux_amd64|g" \
		"$tmpl")"
	case "$formula" in
	*"{{"*) die "the template has a placeholder this script does not fill: $(printf '%s\n' "$formula" | grep -o '{{[^}]*}}' | head -n 1)" ;;
	esac
	[ -n "$formula" ] || die "the filled formula is empty"

	if [ -n "$out" ]; then
		printf '%s\n' "$formula" >"$out" || die "could not write $out"
		echo "wrote $out ($tag)" >&2
	else
		printf '%s\n' "$formula"
	fi
}

main "$@"
