# Changelog

## 0.3.0

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
