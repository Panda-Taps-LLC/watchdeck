# Security policy

watchdeck is an observatory and control plane over Claude Code's own safety settings, plus an OS sandbox where Claude Code has none. A bug that lets an agent do what a rule or a sandbox denies, that lets the model change a rule without you, or that lets a release be swapped unnoticed is a vulnerability. We want to hear about it privately first.

## Reporting

Use GitHub's private vulnerability reporting for this repository:

https://github.com/Panda-Taps-LLC/watchdeck/security/advisories/new

That opens a private thread with the maintainer. Please do not open a public issue or pull request for a security problem. Private vulnerability reporting opens with the public repository; the tree is not distributed before that.

Include what you can of:

- the watchdeck version (`watchdeck version --json`), the operating system and its version;
- `watchdeck doctor --json` and `watchdeck rules list --json` (check both for private paths first);
- the exact command or tool call, the hook's decision and the run's outcome: the matching records of the activity log at `watchdeck paths` → `activity`, scanned for anything private before you send them;
- the `[watchdeck]` trailer, if there was one.

A canary skill under `testdata/skills/` that reproduces the problem is ideal. Never include real credentials or private files in a report; use throwaway files as the fixtures do.

You will get an acknowledgement within seven days. Fixes are released as soon as they are ready, with credit in the release notes if you want it.

## What counts

- A script running under `watchdeck run` reaching something its effective policy denies: network when `network: none`, a write outside the granted paths, a read of a path in the deny list, an environment variable outside the `env` list, or a binary outside an `exec` allow-list on macOS.
- A Bash command that executes a skill's script without being rewritten to `watchdeck run` and without the hook returning `ask`.
- `auto_allow` returning `allow` for a command that is more than the single skill invocation.
- A project `.watchdeck.yaml` granting anything outside the project directory and temp, or network above `localhost`.
- `watchdeck run` executing a script unconfined when the sandbox could not be applied, instead of exiting 126.
- A malformed or hostile manifest that is accepted, or one that removes a built-in deny.
- A grant that reaches a built-in deny path through an absolute or symlinked spelling (`/Users/you/.ssh`, a link to `~/.aws`), from `watchdeck allow`, the dashboard or the in-session mod.
- The dashboard answering an `/api/` request without its token. The token is persistent, mode 0600 in the state dir, and is never sent before the HMAC challenge bound to the listening port, a check that the server answering on that port already holds the token (`watchdeck ui --rotate-token` replaces it). Also: listening on anything but `127.0.0.1`, accepting a request whose `Host` is not `127.0.0.1:<port>` or `localhost:<port>`, or accepting a cross-origin or non-JSON write.
- `watchdeck rules`, `setup`, the dashboard or `uninstall` writing a Claude Code settings string outside the ledger it keeps (the file in which watchdeck records each settings string it wrote), removing a rule it does not own, leaving an owned string behind after `uninstall`, or a settings write made without a backup written first.
- The model widening a grant, adding, removing or switching a rule, or running any mutating `watchdeck` command through Bash without an ask (`TestModelTypedMutatingCommandsAsk`). The hook returning allow for a tool call a gate should deny or ask (`FuzzGatesNeverAllow`).
- The model invoking a user-only slash command (`/watchdeck:open` and `/watchdeck:status`, both `disable-model-invocation: true`).
- The in-session mod running `watchdeck allow`, or any other command, without the person's explicit Grant in its confirm dialog. Also: a grant built from anything but the activity record's structured `ungranted[]`, such as script output, a forged trailer or the hook's reason text; and a binary used from under the project or `$TMPDIR`.
- Text from a skill's output or from a project's `.watchdeck.yaml` that watchdeck echoes in a way that imitates its own reason or trailer (for example a fake "requested but not granted" clause).
- The activity log recording more than `docs/DESIGN.md` section 7 states: anything from stdout or stderr beyond lines that matched a denial pattern (at most 200 bytes each, 8 per run), transcript content, or the dashboard token; or a log file readable by other users. Also: the hook opening the log for a command it has no opinion on.
- Transcript content reaching the dashboard page beyond the compact view (agents, tools, decisions, a 240-character Bash snippet). That includes assistant text, thinking, file contents, absolute file paths, or a transcript outside Claude Code's projects directory being read at all, or read with `--no-transcripts`.
- A release archive whose `checksums.txt` verifies but whose cosign bundle or provenance attestation does not match this repository's release workflow and the tag, or a published binary that differs from a rebuild of the tag with the same Go toolchain (see "Verify a release" below; the archives' tar headers are not asserted reproducible, the binaries are).

## What we do not stop

These are known and documented limits, not vulnerabilities.

- **Prose instructions.** A `SKILL.md` can still talk the agent into misusing Read or WebFetch; only scripts are sandboxed.
- **Auto mode's own decisions.** watchdeck records them and turns them into rules; it does not change how Claude Code's check decides.
- **`bypassPermissions` and `dontAsk`.** Claude Code can settle an ask there without you, so watchdeck's asks drop the sandbox rewrite; a hook ask was run only in `bypassPermissions` under `claude -p`, and `dontAsk` and an interactive `bypassPermissions` session are not verified.
- **A person turning it off.** Anyone who can edit your Claude Code settings can remove the hooks; `watchdeck doctor` says when it is not installed.
- **Shadow mode.** While `watchdeck rules shadow on` is in effect, watchdeck's own rules and gates record what they would have done instead of blocking or asking, while your Claude Code deny and ask rules, the OS sandbox and watchdeck's own asks (a watchdeck command the model typed, an invalid policy file, the watchdog) stay in force ([`docs/DESIGN.md`](docs/DESIGN.md) section 12, known limit 20). A shadow-mode bypass of anything in that list is a vulnerability under "What counts".
- **Commands built at run time.** Words another program produces when the command runs are not seen, including a watchdeck command assembled that way or a name built from pieces.
- **Anything outside Claude Code.** A program running as you that Claude Code did not start is out of reach.
- **Copy-then-run and unrecognised forms.** A command that references no skill path gets no opinion, and an ambiguous command you approve runs unsandboxed; the prompt says so.
- **Network is binary.** `none | localhost | all`, with no hostname filtering; WebFetch domain rules are hook gates, not OS-enforced.
- **Linux is weaker and Windows has nothing.** Linux does not enforce `exec` allow-lists, treats `localhost` as `none`, hides only literal deny paths, and is CI-tested only; the binary does not build for Windows.
- **The dashboard trusts whoever holds its link.** It listens on loopback only, behind a token; anyone who can read the link or the token file, or run code as you, can use it. It is a local tool, not multi-user auth.
- **"Declared versus did" and denial hints are a floor.** A denial the script swallowed, or a command the hook never saw, does not appear; hints are matched from output text.
- **A person's "No" is not recorded**, because Claude Code's `PermissionDenied` hook fires in auto mode only. A Read, Write or Edit call that Claude Code's own deny rule refused shows in the session map, from the transcript, and not in Home's Recent decisions. A Bash call that the hook's mirror of your rules denied shows in both.
- **Rules you add have edges.** The Read rules for SSH and AWS keys cover only your home once Read is unhooked; a recommended rule you removed by hand stays removed; the plugin's hooks file registers every file tool whatever the rules need.

The full lists, each line with its test: the README's "What it does not stop", [`docs/GUIDE.md`](docs/GUIDE.md#what-this-does-not-do) "What this does not do", and the "Known limits" of sections 9 to 12 in [`docs/DESIGN.md`](docs/DESIGN.md).

## Verify a release

Every release ships `checksums.txt`, a keyless cosign bundle `checksums.txt.sigstore.json` and a GitHub build-provenance attestation, all made by this repository's release workflow for the tag. You need cosign 3.x (`brew install cosign`). The identity is bound to the tag, so substitute the tag you downloaded:

```sh
tag=v0.1.0          # the release you downloaded; the archive, checksums.txt and checksums.txt.sigstore.json sit beside each other
cosign verify-blob \
  --certificate-identity "https://github.com/Panda-Taps-LLC/watchdeck/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
grep watchdeck_0.1.0_darwin_arm64.tar.gz checksums.txt | shasum -a 256 -c    # your archive; sha256sum -c on Linux
```

The second channel is Rekor plus the workflow identity, not a second download. A public repository's attestation is recorded in the public Rekor log, and `gh` checks it against the signer workflow. `gh` must be signed in to any GitHub account:

```sh
gh attestation verify watchdeck_0.1.0_darwin_arm64.tar.gz \
  --repo Panda-Taps-LLC/watchdeck \
  --signer-workflow Panda-Taps-LLC/watchdeck/.github/workflows/release.yml
```

A failure means the bundle or the attestation was not made by this repository's release workflow for that tag: a wrong tag in the identity, a re-signed or tampered file, or an archive that is not from that release. Do not install it; report it as above.

The release workflow signs and attests only when GitHub reports the repository's visibility as `public`. Any other value, including an absent one, produces an unsigned draft, and the job summary says so. The first signed release therefore comes with the public repository. An archive without a `checksums.txt.sigstore.json` beside its `checksums.txt` is such an unsigned draft. The installer does these checks for you: `scripts/install.sh --verify` (or `WATCHDECK_VERIFY=1`) runs the `gh` line above on the downloaded archive when `gh` is signed in, else the cosign line on `checksums.txt` with the bundle from the release, and then the sha256 check; it refuses when neither tool is usable, reports a release without the bundle as an unsigned draft, and installs nothing when any of that fails. As of 2026-10-20 it is tested against stubs for both tools (`scripts/test-install.sh`, cases 9 to 14) and is designed, not tested against a real release, until the first public tag.

## Supported versions

There is no release yet (2026-10-20). Once the first release is out, the latest minor release is supported and reports against `main` are welcome. Releases are signed from the public repository only.
