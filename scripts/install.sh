#!/bin/sh
# watchdeck installer. Downloads a release archive, verifies its sha256
# against checksums.txt, installs the binary, links it into ~/.local/bin
# when that is on PATH, and runs `watchdeck setup`. No sudo.
#
# Usage: install.sh [--version vX.Y.Z] [--dir DIR] [--from DIR_OR_FILE_URL]
#                   [--verify] [--no-setup] [--yes]
#
#   --version   release tag (default: latest, from the GitHub API)
#   --dir       install directory (default: ~/.local/share/watchdeck/bin)
#   --from      read watchdeck_<ver>_<os>_<arch>.tar.gz and checksums.txt from
#               a local directory or a file:// base instead of GitHub (tests)
#   --verify    check the release's provenance before installing (also
#               WATCHDECK_VERIFY=1): with the GitHub CLI signed in,
#               `gh attestation verify` on the archive; else with cosign 3.x,
#               the keyless bundle on checksums.txt; else refuse. Nothing is
#               installed when that check fails.
#   --no-setup  install only; do not run `watchdeck setup`
#   --yes       run `watchdeck setup --yes` (applies without asking)
#
# Under `curl | sh` stdin is this script, so setup reads its answers from
# /dev/tty; without a terminal (and without --yes) the installer only
# prints the next step. `watchdeck uninstall` removes everything again.
#
# checksums.txt comes from the same release as the archive, so the sha256
# check detects a corrupt or truncated download, not a tampered release.
# --verify adds that: the GitHub CLI checks the archive against the release
# workflow's build-provenance attestation, or cosign checks the keyless
# bundle on checksums.txt, which the sha256 check then binds to the archive;
# the identity is this repository's release workflow at the release's tag.
#
# The whole script is inside main(), called on the last line, so a truncated
# `curl | sh` runs nothing.

REPO="Panda-Taps-LLC/watchdeck"

die() { echo "install.sh: $*" >&2; exit 1; }

usage() {
	cat <<'USAGE'
Usage: install.sh [--version vX.Y.Z] [--dir DIR] [--from DIR_OR_FILE_URL]
                  [--verify] [--no-setup] [--yes]
  --version   release tag (default: latest)
  --dir       install directory (default: ~/.local/share/watchdeck/bin)
  --from      local directory or file:// base holding the archive and checksums.txt
  --verify    check the release's provenance first (GitHub CLI signed in, or cosign 3.x);
              WATCHDECK_VERIFY=1 does the same; nothing is installed when it fails
  --no-setup  install only; do not run watchdeck setup
  --yes       run watchdeck setup --yes (no questions)
Remove everything later with: watchdeck uninstall
USAGE
}

# valid_version: v<d>.<d>.<d> optionally followed by -[0-9A-Za-z.-]*; no slash,
# no "..", no whitespace.
valid_version() {
	case "$1" in
	*..* | */* | *[[:space:]]*) return 1 ;;
	esac
	printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
}

fetch() { # fetch <url-or-path> <dest>
	case "$1" in
	file://*) cp "${1#file://}" "$2" ;;
	https://*)
		if command -v curl >/dev/null 2>&1; then
			curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2"
		elif command -v wget >/dev/null 2>&1; then
			wget -q --https-only "$1" -O "$2"
		else
			die "need curl or wget"
		fi
		;;
	*)
		[ -e "$1" ] || return 1
		cp "$1" "$2"
		;;
	esac
}

main() {
	set -eu
	version=""
	dir=""
	from=""
	setup=1
	yes=""
	verify=""
	[ "${WATCHDECK_VERIFY:-}" = "1" ] && verify=1

	while [ $# -gt 0 ]; do
		case "$1" in
		--version) [ $# -ge 2 ] || die "--version needs a value"; version="$2"; shift 2 ;;
		--dir) [ $# -ge 2 ] || die "--dir needs a value"; dir="$2"; shift 2 ;;
		--from) [ $# -ge 2 ] || die "--from needs a value"; from="$2"; shift 2 ;;
		--verify) verify=1; shift ;;
		--no-setup) setup=""; shift ;;
		--yes) yes=1; shift ;;
		-h | --help) usage; exit 0 ;;
		*) die "unknown argument: $1" ;;
		esac
	done

	if [ -z "$dir" ]; then
		[ -n "${HOME:-}" ] || die "HOME is not set; pass --dir"
		dir="$HOME/.local/share/watchdeck/bin"
	fi

	case "$(uname -s)" in
	Darwin) os=darwin ;;
	Linux) os=linux ;;
	*) die "unsupported OS: $(uname -s) (darwin and linux only)" ;;
	esac
	case "$(uname -m)" in
	arm64 | aarch64) arch=arm64 ;;
	x86_64 | amd64) arch=amd64 ;;
	*) die "unsupported architecture: $(uname -m) (arm64 and amd64 only)" ;;
	esac

	tmp="$(mktemp -d "${TMPDIR:-/tmp}/watchdeck-install.XXXXXX")"
	trap 'rm -rf "$tmp"' EXIT
	trap 'exit 130' INT TERM

	if [ -z "$version" ]; then
		[ -z "$from" ] || die "--from needs --version"
		fetch "https://api.github.com/repos/$REPO/releases/latest" "$tmp/latest.json" ||
			die "could not look up the latest release (is it published? try --version vX.Y.Z)"
		version="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -n 1)"
		[ -n "$version" ] || die "no tag_name in the latest release response"
	fi
	valid_version "$version" || die "version must look like v0.1.0 (letters, digits, dot, dash only), got: $version"
	# goreleaser names archives with the version without the leading v.
	archive="watchdeck_${version#v}_${os}_${arch}.tar.gz"

	if [ -n "$from" ]; then
		base="${from%/}"
	else
		base="https://github.com/$REPO/releases/download/$version"
	fi

	echo "Downloading $archive ($version)"
	fetch "$base/$archive" "$tmp/$archive" || die "could not download $base/$archive"
	fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "could not download $base/checksums.txt"

	if [ -n "$verify" ]; then
		# Provenance first, then the sha256 check below. The GitHub CLI
		# verifies the archive itself against the release workflow's
		# attestation (its subjects are the archives); cosign verifies the
		# keyless bundle on checksums.txt, which the sha256 check then binds
		# to the archive. Stdin is this script under `curl | sh`, so every
		# tool reads /dev/null. A failure names the tool's first non-blank
		# stderr line (gh prints a blank line before its Error: line).
		# Whatever PATH finds is used, which is how scripts/test-install.sh
		# stubs both tools.
		gh_state="not installed"
		if command -v gh >/dev/null 2>&1; then
			if gh auth status </dev/null >/dev/null 2>&1; then
				gh_state="signed in"
			else
				gh_state="installed but not signed in"
			fi
		fi
		if [ "$gh_state" = "signed in" ]; then
			rc=0
			gh attestation verify "$tmp/$archive" --repo "$REPO" \
				--signer-workflow "$REPO/.github/workflows/release.yml" \
				</dev/null >/dev/null 2>"$tmp/verify.err" || rc=$?
			if [ "$rc" -ne 0 ]; then
				reason="$(sed -n '/[^[:space:]]/{p;q;}' "$tmp/verify.err")"
				[ -n "$reason" ] || reason="exit status $rc"
				die "provenance could not be verified for $archive (gh attestation): $reason; nothing installed"
			fi
			echo "provenance ok (gh attestation)"
		elif command -v cosign >/dev/null 2>&1; then
			fetch "$base/checksums.txt.sigstore.json" "$tmp/checksums.txt.sigstore.json" ||
				die "no checksums.txt.sigstore.json in the release: an unsigned draft; nothing installed"
			rc=0
			cosign verify-blob --bundle "$tmp/checksums.txt.sigstore.json" \
				--certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$version" \
				--certificate-oidc-issuer https://token.actions.githubusercontent.com \
				"$tmp/checksums.txt" </dev/null >/dev/null 2>"$tmp/verify.err" || rc=$?
			if [ "$rc" -ne 0 ]; then
				reason="$(sed -n '/[^[:space:]]/{p;q;}' "$tmp/verify.err")"
				[ -n "$reason" ] || reason="exit status $rc"
				die "signature could not be verified for checksums.txt (cosign bundle): $reason; nothing installed"
			fi
			echo "signature ok (cosign bundle)"
		else
			die "--verify needs the GitHub CLI signed in (gh auth login) or cosign 3.x: gh is $gh_state, cosign is not installed; nothing installed"
		fi
	fi

	want="$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")"
	[ -n "$want" ] || die "$archive is not listed in checksums.txt"
	printf '%s\n' "$want" | grep -Eq '^[0-9a-fA-F]{64}$' || die "checksums.txt has a malformed entry for $archive"
	if command -v sha256sum >/dev/null 2>&1; then
		got="$(sha256sum "$tmp/$archive" | awk '{ print $1 }')"
	elif command -v shasum >/dev/null 2>&1; then
		got="$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')"
	else
		die "need sha256sum or shasum"
	fi
	[ "$got" = "$want" ] || die "checksum mismatch for $archive (expected $want, got $got); nothing installed"
	echo "sha256 ok"
	[ -n "$verify" ] || echo 'Not verified against the release signature; add --verify (see SECURITY.md, "Verify a release")'

	mkdir "$tmp/x"
	tar -xzf "$tmp/$archive" -C "$tmp/x" || die "could not unpack $archive"
	bin="$(find "$tmp/x" -type f -name watchdeck | head -n 1)"
	[ -n "$bin" ] || die "no watchdeck binary in $archive"

	mkdir -p "$dir"
	dir="$(cd "$dir" && pwd)" # absolute, for the link and the hooks
	rm -f "$dir/watchdeck.new"
	cp "$bin" "$dir/watchdeck.new"
	chmod 0755 "$dir/watchdeck.new"
	mv -f "$dir/watchdeck.new" "$dir/watchdeck"
	echo "Installed $dir/watchdeck"

	# A link in ~/.local/bin when that is on PATH; never over a real file.
	onpath=""
	case ":${PATH:-}:" in *":$dir:"*) onpath=1 ;; esac
	bindir="${HOME:+$HOME/.local/bin}"
	if [ -z "$onpath" ] && [ -n "$bindir" ] && [ "$bindir" != "$dir" ]; then
		case ":${PATH:-}:" in
		*":$bindir:"*)
			link="$bindir/watchdeck"
			if [ -L "$link" ] || [ ! -e "$link" ]; then
				mkdir -p "$bindir"
				ln -sfn "$dir/watchdeck" "$link"
				echo "Linked $link -> $dir/watchdeck"
				onpath=1
			else
				echo "Not linking $link: a file that is not a symlink is already there"
			fi
			;;
		esac
	fi
	[ -n "$onpath" ] || echo "Add it to your PATH:  export PATH=\"$dir:\$PATH\""

	# Releases before setup existed (v0.1.0) need enforce install instead.
	if ! "$dir/watchdeck" help 2>/dev/null | grep -q '^  setup '; then
		echo "Next: watchdeck enforce install"
		return 0
	fi
	if [ -z "$setup" ]; then
		echo "Next: watchdeck setup"
	elif [ -n "$yes" ]; then
		echo "Running: watchdeck setup --yes"
		"$dir/watchdeck" setup --yes </dev/null || echo "Setup did not finish; run: watchdeck setup"
	elif [ -t 1 ] && [ -r /dev/tty ] && (: </dev/tty) 2>/dev/null; then
		echo "Running: watchdeck setup"
		"$dir/watchdeck" setup </dev/tty || echo "Setup did not finish; run: watchdeck setup"
	else
		echo "No terminal to ask on. Next: watchdeck setup"
	fi
	echo "To remove everything later: watchdeck uninstall"
}

main "$@"
