# Dependency Audit

A bar badge for the [Omarchy](https://omarchy.org/) shell that watches a
configured list of local project directories for dependency security and
staleness — outdated packages and known CVEs — aggregated across every repo
you work in, so you don't have to remember to run `npm audit` /
`cargo audit` / `pip-audit` / `govulncheck` in each one yourself.

No dashboard, no daemon: a shield icon in the bar shows the total finding
count, color-coded by worst severity. Clicking it opens a per-repo
breakdown — package name, current vs. fixed version, severity, the CVE
number (or native advisory id when no CVE was assigned), and a click-to-copy
fix command.

## Install

```sh
omarchy plugin add https://github.com/thomasvez/omarchy-depaudit.git --enable
```

## Usage

- **Left click**: open/close the per-repo breakdown (Escape also closes)
- **Middle click**, or **`r`** while the panel is focused: re-run every
  project's audit now
- **Right click**: send the current summary as a desktop notification —
  glanceable without opening the panel at all
- **Click a finding**'s CVE/advisory id in the panel: open that advisory's
  page in the browser
- **Click anywhere else** on a finding: copy its fix command to the
  clipboard

## Configure

Nothing runs until you configure at least one project. Add a `projects`
entry to this widget's block in `~/.config/omarchy/shell.json` (hot-reloads
on save):

```json
{
  "id": "io.github.thomasvez.depaudit",
  "refreshIntervalMinutes": 60,
  "projects": [
    { "label": "omarchy-depaudit", "path": "/home/you/Development/Omarchy/omarchy-depaudit" },
    { "label": "work-api", "path": "/home/you/work/api" }
  ]
}
```

- `projects` — the repos to watch, top to bottom in the panel.
  - `path` — absolute path to the project's root directory.
  - `label` — display name in the panel; defaults to `path` if omitted.
- `refreshIntervalMinutes` — how often every repo re-audits in the
  background. Default `60`. Set `0` to disable the recurring timer and rely
  on middle-click / the `r` key instead — audits shell out to package
  registries, so there's a real cost to running them often.
- `icon` — bar glyph, default `🛡`.

Move it in the bar:

```sh
omarchy bar move io.github.thomasvez.depaudit --section right
```

## How detection works

For each configured project, in order:

1. `Cargo.toml` present → `cargo audit --json` (needs `cargo-audit`
   installed: `cargo install cargo-audit`).
2. `package.json` present → `npm audit --json` (needs `npm`).
3. `requirements.txt` present → `pip-audit --format json -r requirements.txt`,
   or `pyproject.toml` present → `pip-audit --format json .` (needs
   `pip-audit`: `pip install pip-audit`).
4. `go.mod` present → `govulncheck -scan module -json` (needs `govulncheck`:
   `go install golang.org/x/vuln/cmd/govulncheck@latest`). Module-level
   scanning checks every declared dependency's version against the vuln DB
   regardless of whether your code actually calls into the vulnerable
   function — matching how npm/cargo/pip audit work, rather than
   govulncheck's default call-graph-reachability mode.
5. None of the above → shown as "no recognized manifest" in the panel.

If the matching tool isn't on `PATH`, that repo shows "not found on PATH"
instead of a false "clean" result — a missing tool is never silently
treated as zero vulnerabilities.

No network calls happen outside what each audit tool itself makes (`npm
audit`, `pip-audit`, and `govulncheck` query their registries/vuln DBs;
`cargo audit` checks a local RustSec DB clone). The plugin itself doesn't
talk to any server.

## Known limitations

- **pnpm / yarn**: a `package.json` repo always runs plain `npm audit`,
  even when its lockfile is `pnpm-lock.yaml` or `yarn.lock`. This can
  resolve a different dependency tree than what's actually installed.
  Native `pnpm audit` / `yarn npm audit` support is a follow-up — their
  JSON shapes differ from npm's and aren't parsed yet.
- **Severity on pip/go findings**: `pip-audit` and `govulncheck` don't
  include any severity data in their JSON output (unlike npm's
  critical/high/moderate/low). Their findings are shown as `unknown`
  severity (amber) rather than a guessed rank. `cargo-audit` findings *do*
  get a real severity — RustSec advisories often carry a CVSS v3.x vector,
  which is scored into critical/high/moderate/low the same as npm's; only
  advisories with no CVSS vector at all (e.g. "unmaintained" notices) fall
  back to `unknown`.
- **No CMake/C++ or other build-system support**: only npm, cargo, pip, and
  Go are covered. There's no single standard audit tool for C/C++
  dependencies the way the others have one.

## Remove

```sh
omarchy plugin remove io.github.thomasvez.depaudit
```
