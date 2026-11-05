# Contributing

watchdeck is a security tool. These rules are not optional.

## Rules

- **No real secrets, ever.** Fixtures, tests, docs and examples use fake paths and fake values (`$HOME/.ssh/id_fake`, `CANARY_SECRET=not-a-real-secret`).
- **Never read the developer's credential files** while developing or testing: `~/.ssh`, `~/.aws`, `~/.gnupg`, `.pem`, access-key CSVs, `.env`. Probe with throwaway files the test creates under a temp `HOME`.
- **Tests never touch the real home.** Every test sets `HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` and `XDG_STATE_HOME` to `t.TempDir()`. Discovery code takes a `Roots{Home, Cwd, Env}` struct and never calls `os.UserHomeDir()` directly. The activity log is on by default, so every script, capture and manual run must also point it at a temp path, through `WATCHDECK_ACTIVITY=<temp>/activity.jsonl` or `XDG_STATE_HOME`; otherwise the developer's real state dir gets written. The session lifecycle records (`sessions.jsonl`, `live/`, M5.2) follow `XDG_STATE_HOME` only, not `WATCHDECK_ACTIVITY`: anything that runs the hook on a SessionStart, SessionEnd or UserPromptSubmit payload sets `XDG_STATE_HOME` to a temp dir (or `WATCHDECK_LIFECYCLE=off`).
- **Sandbox profiles in tests are applied to temp directories only**, never to the developer's home.
- **Do not run a developer's installed skills as test subjects.** Use the canary skills under `testdata/skills/`.
- **Never modify `~/.claude/settings.json` from tests or scripts.** End-to-end tests pass a temporary settings file with `claude --settings <file>`. Never run `enforce install`, or the dashboard's Enforce page, against the real settings while developing.
- **Never read a developer's own Claude Code sessions.** Transcript fixtures come only from a throwaway session (see "Transcript fixtures" below), never from listing or opening `~/.claude/projects`.
- **Every "X is enforced" claim in docs points at a test or a spike** under `spikes/`. If something was not run, write "designed, not tested".
- **Dates in docs are absolute** (`2026-10-11`), never "today" or "recently".

## Development

- Go, latest stable (`brew install go` on macOS).
- `go vet ./... && go test ./...` must pass before a commit.
- **Changes reach `main` by pull request** (ruleset on `main` since 2026-11-04): one approving review from a code owner (`.github/CODEOWNERS`) and every `ci.yml` job green, rebase or squash merge, linear history, no force pushes. Repository admins may bypass; each bypass is logged in the ruleset insights.
- Secret scan: download the gitleaks release the `secrets` job pins (version and sha256 are in `ci.yml`) and run `gitleaks git --redact --config .gitleaks.toml .`; fixtures with fake values are allowlisted in `.gitleaks.toml`.
- macOS enforcement tests need `/usr/bin/sandbox-exec` and skip elsewhere. Linux tests need `bubblewrap`.
- Keep dependencies to the three in `go.mod`: `mvdan.cc/sh/v3`, `github.com/goccy/go-yaml`, `github.com/bmatcuk/doublestar/v4`. The hook runs on every Bash call; startup time is a feature.
- **Hook speed budget.** On the no-opinion path, measured 2026-10-20 over three runs of `scripts/measure-hook.sh` with BEFORE at the Plan 05 close (darwin arm64, 200 spawns each): median 5.1 to 5.3 ms, p95 5.3 to 6.7 ms across the runs (DESIGN section 12). Earlier, on 2026-10-12, the median was 6.7 ms, p95 8.0 ms and the stripped binary 8.64 MB; before the dashboard was linked in, the median was 4.7 ms. On 2026-10-13, after every linked package was made init-free, the median was 5.9 ms and p95 7.3 ms (DESIGN §7). A change that adds more than about 1 ms to the median needs a reason in its commit message and an updated measurement in the current section of `docs/DESIGN.md`. Run the script before and after (`BEFORE=<rev> AFTER=HEAD scripts/measure-hook.sh`). The CI `latency` job repeats the relative check on macos-latest as an advisory (`CHECK=1`, exit 2 becomes a warning); the gate for a tag is the owner's-machine number under "Releasing".
- **Packages linked into the hook must be init-free.** One binary serves both the hook and the dashboard, so no package may do work at init:
  - no package-level `regexp.MustCompile`;
  - no template parsing;
  - no `http.Handle*` registration;
  - no package-level variables initialised by function calls.
  - no package-level map literals (a map is built at init; use a `switch`).

  `//go:embed` and `errors.New("…")` are fine. Use `lazyre.Regexp{Expr: …}` for a package-level regexp and a `sync.Once` for other tables. To check, run `GODEBUG=inittrace=1 ./watchdeck hook </dev/null 2>&1 | grep watchdeck`: no watchdeck package may appear with init work. Two tests in `cmd/watchdeck/initfree_test.go` guard every package the binary links (found with `go list -deps`): one runs the built binary under `GODEBUG=inittrace=1`, the other parses the source of every GOOS and names the offending line. `internal/ui`'s `TestPackageIsInitFree` also bans heavy imports there.

## The dashboard (`internal/ui`)

- **Standard library only.** The server uses `net/http`, `embed`, `encoding/json` and `crypto/*`. The pages are embedded under `internal/ui/static/` and use the system fonts. No new Go dependency, no JavaScript build step, no CDN, no remote font or script.
- **Strict CSP.** Every response carries `default-src 'none'; script-src 'self'; style-src 'self'; …`. That rules out:
  - inline `style=` attributes;
  - `<style>` blocks;
  - inline `<script>` and `on*=` handlers;
  - `setAttribute("style", …)`;
  - `innerHTML` carrying any of the above.

  Set dynamic values through CSSOM (`el.style.transform = …`) instead. `static_test.go` checks the static files.
- **Tests bind `127.0.0.1:0` and never open a browser.** Use `ui.Listen(0)` plus `Serve` in a goroutine, not `httptest.NewServer`: the Host check needs the real port. Never bind a non-loopback address, even in a test.
- **Every new route goes under `/api/`** so the guard applies to it: Host check, token, Origin and content type on writes, body cap. Add a test showing the route answers 401 without the token. Side effects happen only after the bearer check.
- **Manual browser checks** use a fixture HOME (`testdata/home` plus the canaries in a temp dir, temp XDG dirs), never the real one. Look at the console: it must show zero CSP violations.
- **Do not commit `.playwright-mcp/`.** Playwright MCP writes console logs and page snapshots there, and they can hold the launch URL with its token. Screenshots for docs come only from the fixture HOME, stay under 300 KB, and get a provenance entry (command, fixture, versions, viewport, date) in `docs/images/README.md`.

## The in-session mod (`plugin/`)

The plugin is a set of command hooks (`plugin/hooks/hooks.json`) plus a Claude Code hooks module (`plugin/hooks/register.tsx` and its imports). It has no npm dependencies and no build step. Dev loop:

1. `claude plugin validate plugin --strict` must pass. It reports the hooks and the `$` calls the module uses; keep them to the documented set.
2. Load the plugin once with `claude --plugin-dir ./plugin --settings <temp settings>`. Claude Code then writes `claude-code.d.ts` and a tsconfig into `plugin/.claude-plugin/types/`, which is gitignored and never committed. After that, type-check with `bun x tsc -p plugin` or `npx -p typescript tsc -p plugin`.
3. `claude plugin test plugin` must pass. Every test sets `HOME` and `XDG_STATE_HOME` to temp paths with `mock.env` and isolates the store with `mock.store`. Process and file access are answered by the test's own hooks, never by the real machine. Run UI tests over both the terminal and desktop surfaces.

The temp settings file for a `--plugin-dir` session holds only `permissions.allow` and `sandbox.excludedCommands`. A file from `enforce install --file` would register the hook a second time, beside the plugin's own.

The grant path is the one place the mod runs a command with the user's privileges. Any change to it needs a test that Cancel runs nothing, and a test that output text from a script cannot shape the argv.

## Transcript fixtures

Transcript fixtures under `internal/transcript/testdata/` come only from a throwaway session, in three steps:

1. **Capture.** `WATCHDECK_FIXTURE=1 scripts/fixture-session.sh [--out DIR] [--skill NAME]` runs one `claude -p` session in a temp project with temp settings and temp XDG dirs; it costs a few API tokens. By default the transcript lands in the normal Claude Code projects dir, because credentials do not follow a relocated config dir; the script copies out exactly that one session file and its `subagents/` by exact path, and never lists anything else. `--isolated [DIR]` sets `CLAUDE_CONFIG_DIR` instead; it works only for a DIR under which `claude login` was run once, or with an API key in the environment.
2. **Scrub.** The script runs `scripts/scrub-transcript.py`, which:
   - drops every `attachment` row except `hook_success`;
   - drops `stop_hook_summary` rows and `serverClassifierContext` fields;
   - rewrites the home path to `/Users/you` and the project to `/Users/you/proj`;
   - replaces the email with `you@example.com`.
3. **Review.** The script prints a review grep at the end, which must print nothing: `grep -rn -i -E '<your-login>|@|organizationUuid|serverClassifier|sk-ant|AKIA|prompt_snapshot|credential_org|stop_hook_summary|"signature"' <out> | grep -v 'you@example\.com'`. Then read every file by hand before copying it into `testdata/`. Delete the unscrubbed copies the script leaves under its work dir.

## Design of record

`docs/DESIGN.md` is the single source of truth for how watchdeck works and what has been verified; §7 covers the dashboard, activity log, agent map and in-session mod, including the threat model. Update it rather than writing parallel notes. `README.md` is the short user-facing front page and `docs/GUIDE.md` the full user guide (commands, limits, troubleshooting), and `spikes/seatbelt/` holds the experiments the design's verified claims rest on.

## Releasing

Only the owner tags. Before a tag, on the owner's Mac:

1. `go vet ./... && go test ./...`, `claude plugin validate plugin --strict`, `claude plugin test plugin` (CI runs these too; run the plugin tests by hand only if CI cannot), and `scripts/test-install.sh` PASS.
2. The hook fast path: three runs of `scripts/measure-hook.sh` with BEFORE at the previous tag (or the previous milestone close) and `AFTER=HEAD`. The no-opinion median on this machine must be at or under 8 ms in every run and within the script's +1/+2 ms acceptance. Write the medians, p95s and the date into GUIDE's hook-cost line, the speed budget above and DESIGN's current section.
3. `watchdeck doctor --prove` on the owner's real install reports PASS on all five checks.
4. The pinned tool versions in `ci.yml` (`staticcheck@`, `govulncheck@`, `@anthropic-ai/claude-code@`, the gitleaks tarball and its sha256) are at most a quarter old; Dependabot does not watch them. Re-pin quarterly; `TestCIJobsPinTheirContract` holds the gitleaks URL and digest as literals, so a re-pin edits that test too.
5. CHANGELOG: move `[Unreleased]` under the version and date. Bump the `plugin.json` and `marketplace.json` versions if the plugin changed.
6. Flip (once). The first signed release needs the public repository, and GitHub refuses the settings below on a private one. Before the first tag, from the owner's signed-in `gh`, in this order:
   1. Visibility public: `gh api -X PATCH repos/Panda-Taps-LLC/watchdeck -f visibility=public`, then `gh api repos/Panda-Taps-LLC/watchdeck --jq .visibility` prints `public`.
   2. Fork pull requests from every outside collaborator wait for approval before their workflows run: `gh api -X PUT repos/Panda-Taps-LLC/watchdeck/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors` (204; on 2026-11-04 the private repository answered 422), then the GET of the same path prints `all_external_contributors`.
   3. Private vulnerability reporting, the channel SECURITY.md names: `gh api -X PUT repos/Panda-Taps-LLC/watchdeck/private-vulnerability-reporting` (204), then `gh api repos/Panda-Taps-LLC/watchdeck/private-vulnerability-reporting --jq .enabled` prints `true`.
   4. CodeQL default setup: `gh api -X PATCH repos/Panda-Taps-LLC/watchdeck/code-scanning/default-setup -f state=configured` (200 or 202; 403 means code scanning is not available to the repository: not public, or archived), then `gh api repos/Panda-Taps-LLC/watchdeck/code-scanning/default-setup --jq .state` prints `configured`.
   5. Secret scanning with push protection: `gh api -X PATCH repos/Panda-Taps-LLC/watchdeck -f 'security_and_analysis[secret_scanning][status]=enabled' -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'`, then `gh api repos/Panda-Taps-LLC/watchdeck --jq .security_and_analysis.secret_scanning_push_protection.status` prints `enabled`.
   6. The ruleset on `main` is still active: `gh api repos/Panda-Taps-LLC/watchdeck/rulesets --jq '.[] | select(.name == "main") | .enforcement'` prints `active`. Pull requests stay the route to `main` for everyone but a logged admin bypass ("Development" above); the flip changes no rule.
7. Tag `vX.Y.Z` on main and push the tag. The release workflow leaves a DRAFT. While the repository's visibility is not public, the draft is unsigned and has no attestation (the job summary says so); the first signed draft needs the public repository.
8. Verify the draft, then the release: `scripts/verify-release.sh vX.Y.Z --draft` downloads the four archives, the four `.sbom.json`, `checksums.txt` and `checksums.txt.sigstore.json`, runs the cosign and `gh attestation verify` blocks from SECURITY.md's "Verify a release" on every archive, checks every sha256 and runs `watchdeck version` from the host's own archive; it prints one line per check and exits 1 on any failure. Publish only on a clean run. Then `scripts/verify-release.sh vX.Y.Z` once more against the published assets.
9. The Homebrew formula: `gh release download vX.Y.Z --repo Panda-Taps-LLC/watchdeck --pattern checksums.txt` fetches the published file the previous step verified (the bundle signs it), then `scripts/tap-formula.sh vX.Y.Z checksums.txt --out Formula/watchdeck.rb` inside a checkout of the tap repository `Panda-Taps-LLC/homebrew-tap`; commit and push it there (the formula is hand-committed from the owner's Mac; the release workflow holds no credential for the tap). Then, on the owner's Mac, `brew install Panda-Taps-LLC/tap/watchdeck && watchdeck version` prints the version.
10. The README's install lines resolve against the published release, in a temp HOME so the owner's own install and settings are untouched: `HOME=$(mktemp -d) sh -c 'curl -fsSL https://raw.githubusercontent.com/Panda-Taps-LLC/watchdeck/main/scripts/install.sh | sh -s -- --verify --no-setup'` installs the verified binary under that HOME (that HOME has no signed-in `gh`, so `--verify` takes the cosign path: cosign 3.x must be installed), and `/plugin install watchdeck --marketplace Panda-Taps-LLC/watchdeck` is accepted by Claude Code.

## License

Apache-2.0, chosen 2026-10-12. The full text is in `LICENSE`; the copyright notice is in `NOTICE`. By contributing you agree that your contribution is licensed under Apache-2.0 as described in section 5 of the license. No separate contributor agreement is required. Per-file license headers are not used in this repo.
