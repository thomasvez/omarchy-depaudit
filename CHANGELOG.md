# Changelog

## 0.8.0

- Added an in-panel settings form: click the ⚙ next to the header to edit
  `icon`, `refreshIntervalMinutes`, `discoverRoots`, and `projects` without
  hand-editing shell.json. `discoverRoots`/`projects` are edited as plain
  multi-line text (one entry per line, `label | path` for projects) rather
  than a dynamic add/remove list — far less QML, and copy-paste friendly.
  Saves through `bar.shell.updateEntryInline` — the same first-party
  mechanism the bar's own drag-to-reorder uses to persist a widget's inline
  settings — rather than a bespoke shell.json write of our own.
- The multi-line fields use a small custom component (plain `TextEdit` in a
  themed `Rectangle`+`Flickable`) since qs.Ui has no multi-line control to
  reuse; styled only with helpers already proven working elsewhere in this
  file (`Qt.darker`, `Util.alpha`, `Color.accent`) rather than the kit's
  internal `Style.controlFill`/`Border.controlSpec`, whose exact signatures
  weren't independently verified.
- `PanelKeyCatcher` is now blocked while the settings form is open — it
  intercepts keys before children by design (`Keys.priority:
  Keys.BeforeItem`), and without this, typing "r" into any settings field
  would also trigger a refresh.
- Verified live: opened the form via a temporary debug trigger (no
  `ydotool` available in this environment to click the real gear icon) and
  confirmed the draft fields populate with the actual configured values —
  not just defaults — including a real `discoverRoots` path and a real
  `projects` entry formatted exactly as `Model.rootsToText`/
  `projectsToText` produce them.
- 4 new tests (51 total) for the settings-text conversion helpers
  (`parseProjectsText`/`projectsToText`/`parseRootsText`/`rootsToText`).
- Widened the panel (420px → 600px) — paths and the new settings fields
  need the room. Considered making the panel open centered on the whole
  screen rather than anchored below the bar; every panel in this shell
  (weather, tailscale, network, ...) is built on a shared component that
  only centers along the bar's own axis, never vertically for a top bar,
  so true center-of-screen would mean a custom popup losing that
  component's free outside-click dismiss / multi-monitor handling /
  keyboard-focus / bar-popout-coordination — stayed with the shared
  component and its bar-anchored (but now wider) positioning instead.

## 0.7.0

- Added pnpm and yarn (classic) support. A `package.json` repo now checks
  its lockfile: `pnpm-lock.yaml` → `pnpm audit --json` (npm's *legacy*
  per-advisory-id schema, not the per-package one npm 7+ uses — verified
  against a real pnpm 11.24 run), `yarn.lock` → `yarn audit --json`
  (newline-delimited JSON, one object per line — verified against a real
  yarn 1.22 run), else plain `npm audit` as before. Fixes the known gap
  where a pnpm/yarn project silently ran npm's audit against a lockfile
  that wasn't actually the resolved one.
- Fixed a real bug: a configured project whose path doesn't exist at all
  (typo, moved/deleted repo) fell through every manifest check and was
  misreported as "no recognized manifest" — same message as a real project
  genuinely missing one. Now checked first and reported distinctly.
- Added project auto-discovery: a `discoverRoots` array of directory paths
  gets walked (depth 3, dependency/build directories like `node_modules`
  pruned) for recognized manifests, merged with any explicit `projects`
  entries. Re-run at the top of every refresh, so a project added later
  under a configured root shows up without a shell.json edit.
- Added ignore/dismiss: click "Dismiss" on a finding to exclude it from the
  badge count and severity summary without deleting it from the list —
  reversible via "Restore". Persisted locally (not into shell.json) at
  `~/.local/state/omarchy-depaudit/state.json`, scoped per repo+finding so
  dismissing a CVE in one project doesn't affect the same CVE elsewhere.
- Added proactive new-finding notifications: after any scan, findings not
  present in that repo's previous successful scan trigger one desktop
  notification for the batch. A repo's first-ever scan never counts as
  "new" (would notify on every fresh install), and a scan that fails
  (missing-tool, parse-error) leaves that repo's baseline untouched rather
  than reading "found nothing because it errored" as "everything got
  fixed". Verified live: introduced a real new CVE into a previously-clean
  demo repo, rescanned, and confirmed the exact expected message
  ("2 new findings: minimist (GHSA-...), minimist (GHSA-...)") in the
  system notification history.
- 13 new tests (47 total) covering every addition above, including a
  self-contained temp-directory fixture for discovery (portable to CI,
  not dependent on this machine's own demo state).

## 0.6.1

- Added a real automated test suite (`tests/model.test.js`, Node's built-in
  `node:test`, zero dependencies): 30 tests covering every parser and
  helper in Model.js. Fixtures under `tests/fixtures/` are real captured
  output from the actual tools, not hand-written approximations — every
  parser bug found during development this project's history was caught by
  testing against real tool output, so the regression tests are built the
  same way.
- Added a GitHub Actions workflow (`.github/workflows/test.yml`) running
  `node --check` and the test suite on every push/PR.
- Added `.gitignore` (excludes `NOTES.md` — session-briefing scratch, not a
  project deliverable — plus routine editor/OS cruft) and a minimal
  `package.json` (`npm test`, zero dependencies).

## 0.6.0

- Repo sections are now collapsible, collapsed by default. A severity-count
  row (e.g. "2 critical  1 high") sits right under each header whether
  collapsed or expanded, so a long project list doesn't dump every finding
  on screen at once — click a header to expand it for the full list.
- Added per-project rescan: a small ⟳ glyph on each header re-audits just
  that one repo instead of every configured project. Reuses
  `buildAuditScript`/`parseAuditOutput` with a single-element projects
  array and splices the result back into `repos` at the right index.
- Bulk refresh and a per-project rescan now guard against running
  concurrently — both write into `repos` on completion (one wholesale, one
  by index), so letting them overlap risked one clobbering the other's
  result.

## 0.5.0

- Added Ruby support: `Gemfile.lock` → `bundle-audit check --format json`
  (needs an already-resolved lockfile committed — bundle-audit only reads
  one, it doesn't run `bundle lock` to generate one). Ruby is the first
  ecosystem here with real severity built in (`advisory.criticality`), no
  CVSS math needed like cargo, and its link goes to RubySec's own dedicated
  advisory page (verified live) rather than `advisory.url`, which has the
  same "arbitrary external reference" problem cargo's did before 0.4.1.
- Added .NET support: `*.csproj` / `*.sln` / `*.fsproj` →
  `dotnet list package --vulnerable --include-transitive --format json`
  (a built-in dotnet CLI subcommand, not a separate tool to install).
  Sparser output than every other tool here — no CVE field and no
  fixed-version info at all, just a GHSA advisory URL — so its fix command
  is a generic re-add to latest rather than a specific pin.
- Prepended `~/.dotnet` to the audit script's PATH (same fix as 0.3.0's
  `~/.cargo/bin` — dotnet-install.sh's common manual-install location isn't
  on the bar process's session PATH by default either).

## 0.4.1

- Cargo findings' link now opens RustSec's own advisory page
  (`rustsec.org/advisories/<id>.html`, verified live) instead of
  `advisory.url` — that field is whatever external reference the
  advisory's author happened to pick, often just a GitHub issue thread on
  the affected package's own repo rather than a page about the finding
  itself. pip and go's links already pointed at their own database's
  dedicated page (osv.dev, pkg.go.dev/vuln); this makes cargo consistent.

## 0.4.0

- Each finding now shows its CVE number (preferring a real `CVE-YYYY-NNNNN`
  id from the advisory's aliases, falling back to the native source id —
  GHSA/RUSTSEC/PYSEC/GO — when no CVE was assigned) as a clickable link that
  opens that advisory's page in the browser.
- Fixed a real coverage bug found while wiring this up: npm audit's `via`
  array can hold *multiple distinct* GHSA advisories for one package —
  verified against a real run where minimist matched both a moderate and a
  separate critical advisory — and the parser kept only the first, silently
  dropping the rest. Now emits one finding per advisory.

- Cargo findings now get a real severity instead of a blanket `unknown`:
  `cargo-audit` advisories often carry a CVSS v3.x vector at
  `advisory.cvss` (missed in 0.2.0 — the code only checked for a plain
  `severity` field, which cargo-audit's JSON never has). Added
  `cvssBaseSeverity` to score that vector using the standard CVSS v3.1 base
  formula, bucketed into the same critical/high/moderate/low scale as npm.
  Verified against a real cargo-audit 0.22.2 run: RUSTSEC-2020-0071 scores
  6.2, matching that CVE's published NVD score (6.2 MEDIUM) exactly.
  Advisories with no CVSS vector (e.g. "unmaintained" notices) still fall
  back to `unknown`.
- Fixed a real environment bug: the bar/shell process runs under a
  systemd/PAM-managed session whose PATH is fixed at session start, not the
  PATH a terminal gets. Installers for per-user toolchains (rustup's
  `.cargo/env`, in particular) typically only append to shell rc files,
  which that session never sources — restarting the shell doesn't help
  either, since it isn't a login shell. A rustup-installed `cargo-audit`
  stayed invisible to a live widget across an `omarchy restart shell` while
  present on PATH in a terminal the whole time. The generated script now
  prepends `~/.cargo/bin`, `~/go/bin`, `~/.local/bin`, and
  `~/.local/share/mise/shims` to its own PATH before any `command -v`
  check, so a freshly-installed tool works without a full logout/login.
  Verified by running the pipeline with those directories deliberately
  excluded from the ambient PATH.

## 0.2.0

- Added Go support: `go.mod` → `govulncheck -scan module -json`. Like pip,
  the Go vulnerability DB carries no severity field, so findings are
  bucketed `unknown`; unlike cargo's range-only fix info, `govulncheck`
  reports an exact fixed version, so its fix command
  (`go get module@version`) is always precise rather than advisory-only.
- Fixed a real bug (caught by running against actual `pip-audit` output
  rather than assumed shape): `pip-audit`'s JSON is `{"dependencies": [...],
  "fixes": [...]}`, not a bare top-level array — the parser was reading the
  wrong shape and would have silently reported zero findings on every real
  repo.
- Fixed a second real bug: the generated script ran bare `pip-audit --format
  json` with no target, which audits pip-audit's own Python environment
  instead of the repo being checked. Now passes `-r requirements.txt` or the
  project-path positional for `pyproject.toml`.
- `govulncheck`'s `-json` output is a stream of concatenated top-level JSON
  values, not one document — added `parseJsonStream` (brace/string-aware
  splitter) to pull it apart before parsing individual `finding`/`osv`
  objects.

## 0.1.0

- Initial scaffold: bar badge aggregating `npm audit` / `cargo audit` /
  `pip-audit` findings across a configured list of project directories.
- Per-repo panel with severity, current → fixed version, and a
  click-to-copy fix command per finding.
- Known limitations, tracked as open follow-ups:
  - `package.json` always routes to `npm audit`, even when the repo's
    lockfile is `pnpm-lock.yaml` or `yarn.lock` — pnpm/yarn have different
    audit JSON shapes that aren't parsed yet.
  - `cargo audit` and `pip-audit` findings have no severity field in their
    JSON output, so they're bucketed as `unknown` (amber) rather than a
    real critical/high/moderate/low rank.
  - No keyboard row navigation in the panel yet (Escape/Tab work; Up/Down
    selection + Enter-to-copy do not).
