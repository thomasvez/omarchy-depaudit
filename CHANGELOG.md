# Changelog

## 0.11.1

Fixes three issues raised by the Omarchy plugin marketplace's security
review during submission.

- Hard cap on collected audit/discovery output (100 MiB): StdioCollector
  has no size limit of its own, so a malicious project or a compromised
  registry/advisory response one of the real audit tools fetches could
  otherwise make the shell retain and try to parse an arbitrarily large
  result, exhausting memory. Every generated script's process is now
  killed (SIGKILL) the moment its collected output crosses the cap, and
  every project that was part of that run reports a distinct, bounded
  "output-too-large" status instead. 100 MiB is calibrated against real
  data, not a guess — a real (legitimate, non-malicious) large yarn
  monorepo audited during this project's own development produced 30.4 MB
  of raw output, so a lower cap would have broken real repos, not just
  stopped hostile ones.
- Forced `textFormat: Text.PlainText` on every Text element that can
  render registry/project-controlled strings (package names, versions,
  advisory ids/titles, fix commands, repo labels, paths) — Qt's default
  rich-text handling can otherwise interpret crafted markup in that data
  (including loading external resources via `<img>`), which a malicious
  package name or advisory title could exploit.
- Guarded the predictable `state.json` path against a symlink (dangling
  or not) or an implausibly large file placed there before the plugin
  ever runs: a one-time check now confirms it's either absent or a plain
  regular file under 1 MiB before this FileView is ever pointed at the
  real path, and before any write is allowed through it.
- Found and fixed a real bug in the output-cap fix itself while verifying
  it live: the cap check used `QByteArray.length`, which isn't a reliable
  JS-exposed property via this QML binding — every process was being
  killed on its very first byte of output, breaking the whole plugin
  (empty project list). Switched to the guaranteed-correct `text.length`
  (the collector's JS string) and reverified against real data (a
  325-finding scan across 4 real repos) before considering this done.
- 1 new test (62 total).

## 0.11.0

- Removed dismiss/ignore: this plugin's job is to surface what your audit
  tools actually report, not to curate or hide findings — that decision
  belongs to the person reading the results, not the tool showing them.
  Removed the "Dismiss"/"Restore" control, the `ignoredMap` state (and its
  half of `state.json` — only the new-finding baseline is persisted now),
  and every count/aggregate that used to exclude ignored findings.
- The project list now appears immediately on open/refresh instead of
  staying blank (first run) or stale (re-run) while discovery/audit — both
  potentially slow — are still in flight: a project already scanned keeps
  its real result on screen, anything newly configured or just discovered
  shows up right away as "pending" (existing status, previously only used
  for a truncated-output edge case) until its own result comes in.
- Made "click a project to see its findings" more visually obvious: the
  whole row now highlights on hover (same treatment finding rows already
  use), and the disclosure arrow is bolder and accent-colored on hover —
  previously just a static gray "›", easy to miss as a click target
  without already hovering it.
- 61 tests total (65 → 61): removed the ignore/dismiss tests along with
  the feature, added one for `buildPendingRepos`.

## 0.10.3

- "unknown" severity findings now show as "no CVSS data" with their own
  neutral gray, instead of sharing "low"'s yellow. Prompted by a real
  question: why does a cargo finding show "unknown"? Checked a real repo
  (RustScan) — every one of its 5 real findings has `"cvss": null`
  straight from `cargo audit`'s own JSON. That's RustSec genuinely never
  assigning a severity to that advisory, not a parsing gap (cvssBaseSeverity
  already scores a vector correctly when one exists — verified earlier
  against RUSTSEC-2020-0071, matching NVD's 6.2 exactly) — but sharing
  "low"'s color visually claimed a rating that was never actually made.
  Applies everywhere severity is shown: the finding tag, the per-repo
  severity-count row, the detail view's filter chips, and the header's
  "worst: …" text.
- 2 new tests (65 total).

## 0.10.2

Audited every ecosystem for the same two bug shapes just found in yarn/.NET
(duplicate findings, and workspace fragmentation) rather than leaving them
fixed only where they happened to be reported.

- Fixed the same duplicate-finding shape in .NET: `dotnet list package
  --vulnerable` at a `.sln` reports results *per project*, so a package
  several projects in one solution all reference (common in a real
  multi-project solution) repeated once per project. Proven with a
  synthetic 2-project solution sharing one vulnerable package (2 findings
  instead of 1 before this fix). `parseDotnetAudit` now dedupes by
  package+advisory.
- Fixed the same workspace-fragmentation shape (as 0.10.0's JS-workspace
  fix) for Cargo: verified directly against a real cargo workspace that
  `cargo audit` run inside a member crate directory fails outright
  ("Couldn't load Cargo.lock" — only the workspace root has one), unlike a
  genuinely standalone crate with no committed lockfile (cargo generates
  one on the fly and audits fine — confirmed live). Discovery now drops a
  Cargo.toml with no Cargo.lock of its own when an ancestor directory has
  both its own Cargo.toml *and* Cargo.lock, the same rule 0.10.0 added for
  package.json, generalized to cover both.
- Checked the remaining ecosystems and left them alone with reasons:
  npm/pnpm's audit JSON is already keyed by package/advisory id (can't
  structurally duplicate); pip/Go/Ruby resolve to one locked version per
  dependency with no shared-lockfile "workspace" concept in mainstream use
  (nothing to fragment or duplicate).
- 2 new tests (63 total).

## 0.10.1

- Fixed a real bug the new detail view (0.10.0) made visible: the same
  finding showing up dozens of times in a row. `yarn audit --json` emits
  one `auditAdvisory` event per dependency *path* that reaches a
  vulnerable package, not per distinct vulnerability — in a large
  workspace where many members pull in the same package, that's one event
  per member. Found live in a real repo where a single `tar` advisory
  alone accounted for well over 100 of a 3301-finding total.
  `parseYarnAudit` now dedupes by `advisory.id` (yarn's own stable id for
  the advisory record, distinct from the per-occurrence `resolution.id`) —
  verified against a fresh real audit of the same repo: 3301 → 314 real
  distinct findings. Two genuinely different advisories for the same
  package (this file's own `minimist` fixture, two separate real CVEs)
  are unaffected — still both reported.
- 1 new test (61 total).

## 0.10.0

- Clicking a repo now opens its findings in a dedicated, wider detail view
  (panel widens from 600px to 860px while it's open) instead of expanding
  the list inline. A repo with a lot of findings made the inline expand
  genuinely slow — every finding's row got built at once, reflowing the
  whole popup's height — found via a real yarn workspace with 3000+
  findings in one repo (see below) that made the panel visibly stutter.
  The detail view adds:
  - Severity filter chips (all/critical/high/moderate/low/unknown), each
    labeled with how many of the repo's findings match.
  - Pagination, 20 findings per page — caps how many finding rows exist at
    once regardless of the repo's real total, which is what actually fixes
    the slowness (verified live against a real 3301-finding repo: chips
    and page rendered promptly, only 20 rows ever mounted).
  - "‹ Back" (or Escape) returns to the repo list; the rescan glyph now
    lives in the detail view's header instead of the list row.
- Added a way to scan discoverRoots for new projects without re-auditing
  everything already known: a 🔎 button next to the settings gear (only
  shown when discoverRoots is configured) re-runs discovery and audits
  only the projects not already in the list, leaving existing repos'
  results untouched. `refresh()` (timer/manual) still re-checks every
  configured project as before — this is for "did I just clone something
  new" without paying for a full re-audit.
- Fixed a real discovery bug, found live via a freshly-cloned yarn
  workspace (Backstage-style: root package.json+yarn.lock declaring
  `workspaces: ["packages/*", "plugins/*"]`): workspace members
  (packages/app, packages/backend — no lockfile of their own) each
  discovered as their own bogus "project", fell back to a broken plain
  `npm audit` (no package-lock.json to audit against), and reported no
  results — "many entries, no results". `parseDiscoveredProjects` now
  drops a lockfile-less package.json when an ancestor directory has both
  its own package.json *and* a lockfile — that ancestor's audit already
  covers it. The same rule also correctly drops non-workspace
  scaffold/template package.json files nested under a real project root
  (found in the same repo: a Backstage software-template placeholder with
  `"name": "${{ values.name }}"` and no real dependencies). A package.json
  dir that has its own lockfile is never dropped by this rule.
- Fixed a matching regression in 0.9.1's maxdepth 3→5 change, found live
  against a real 6-project .NET solution: a `.csproj`/`.fsproj` nested
  under a directory with its own `.sln` now gets dropped the same way — a
  `.sln`'s `dotnet list package --vulnerable --include-transitive` already
  resolves everything it references, so the solution no longer fragments
  into one bogus "project" per nested `.csproj`.
- 6 new tests (60 total): the two discovery fixes above, plus the detail
  view's filter/pagination helpers (`Model.filterFindings`,
  `Model.countAllBySeverity`, `Model.paginateFindings`).

## 0.9.2

- Added a way to scan discoverRoots for new projects without re-auditing
  everything already known: a 🔎 button next to the settings gear (only
  shown when discoverRoots is configured) re-runs discovery and audits
  only the projects not already in the list, leaving existing repos'
  results and expand/collapse state untouched. `refresh()` (timer/manual)
  still re-checks every configured project as before — this is for "did I
  just clone something new" without paying for a full re-audit.
- Fixed a real regression from 0.9.1's maxdepth 3→5 change, found while
  verifying the above live against a real repo: discovery now also
  matches `.csproj`/`.fsproj` files nested several levels under a
  directory that already has its own `.sln` — before this fix, a real
  6-project .NET solution (root `MockServer.API.sln` plus a `.csproj` per
  project under `src/`) fragmented into 7 redundant "projects" instead of
  the 1 the solution actually represents, since `dotnet list package
  --vulnerable --include-transitive` at the `.sln`'s own directory already
  resolves everything it references. `parseDiscoveredProjects` now drops
  a `.csproj`/`.fsproj` match nested under a directory with its own
  `.sln`; every other manifest type (including a legitimately nested
  Cargo.toml or package.json in a monorepo) is unaffected.
- 2 new tests (54 total).

## 0.9.1

- Fixed a real discovery bug found via user report (a cloned .NET project
  wasn't detected): `discoverRoots`' walk used `-maxdepth 3`, too shallow
  for the common .NET layout `RepoRoot/src/ProjectName/ProjectName.csproj`,
  which sits 4 levels below a discoverRoot that's the *parent* of RepoRoot
  — one past where 3 would still look. The reported repo happened to also
  have a root `.sln` at depth 2, so it wasn't actually missed by that rule
  alone; the real cause was that it simply hadn't been scanned yet since
  being cloned (confirmed via `state.json`'s baseline, fixed by a manual
  refresh). But the shallow maxdepth was a genuine latent bug for any
  same-shaped repo with no root `.sln`/`.csproj` — only the nested project
  file — which would have been silently skipped. Bumped to `-maxdepth 5`.
- 1 new test (53 total): a synthetic repo with only a deeply-nested
  `.csproj` and no shallow manifest to accidentally save it.

## 0.9.0

- Supported ecosystems are now visible in the plugin itself, not just the
  README: a "Supports: npm · pnpm · yarn · cargo · pip · Go · Ruby · .NET"
  caption sits under the panel header, always visible regardless of state.
  Backed by one `Model.SUPPORTED_ECOSYSTEMS` list so the panel and
  `manifest.json`'s description (which the marketplace catalog card
  displays) can't drift apart from what the plugin actually detects.
- Updated `manifest.json`'s description and `barWidget.description` to
  name every supported ecosystem explicitly, in preparation for listing on
  the Omarchy plugin marketplace.
- 1 new test (52 total).

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
