// Pure logic for the dependency-audit widget: building the per-repo probe
// script, parsing each package manager's audit JSON into one normalized
// shape, and aggregating severities for the bar badge. No QML/Quickshell
// APIs here — only the script text and the Process's stdout ever touch
// those, in Panel.qml.

// Marker line printed before each repo's audit output, so one combined
// stdout stream can be split back into per-repo chunks. The body carries
// only "<projectIndex>|<manager>" — label/path come back from the
// `projects` array by index rather than being round-tripped through the
// shell, so a path or label containing "|" (or newlines) can't desync the
// parse the way embedding that free text in the marker would.
var REPO_MARKER = "===DEPAUDIT-REPO==="

// Single-quote a string for bash. Matches qs.Commons.Util.shellQuote — kept
// as a local copy so this file stays dependency-free and testable outside
// QML. Every project path/label from shell.json is user-controlled config
// embedded into a generated shell script, so this quoting is load-bearing,
// not cosmetic.
function shellQuote(value) {
  return "'" + String(value === null || value === undefined ? "" : value).replace(/'/g, "'\\''") + "'"
}

// GNU/POSIX find treats a bare argument starting with "-" as an option or
// predicate, not a path, when it's in path-list position — shellQuote
// only prevents the shell from splitting/expanding the string, it says
// nothing about how find itself interprets a fully-formed single token.
// A discoverRoot or project path of exactly "-delete" (a real find
// primary needing no further arguments to match) would make find default
// to searching "." — the generated script's own working directory — and
// delete every file found there, since find never actually receives a
// path argument at all. Every path here is documented to already be
// absolute (starts with "/"), which is itself unambiguous to find, but
// nothing currently enforces that; prefixing anything that doesn't
// already start with "/" with "./" guarantees the result can never be
// mistaken for an option, and is a no-op for any already-correct
// absolute path.
function findSafePath(path) {
  var p = String(path || "")
  return p.charAt(0) === "/" ? p : ("./" + p)
}

// Sanitized because Text elements with AutoText rich-text-parse a crafted
// setting (e.g. a label containing "<img src=...>"). Strips the characters
// that could smuggle markup into the long-lived shell process.
function plainText(value) {
  return String(value === null || value === undefined ? "" : value).replace(/[<>&]/g, "")
}

// A fix command (e.g. "npm install pkg@version") is built from package
// name/version fields that ultimately come from a registry or advisory
// response, then copied to the clipboard as-is on click. If one of those
// fields ever contained an embedded newline, pasting the copied text into
// a terminal would run whatever followed the newline as its own command
// the instant Enter is hit — before the user ever gets to review it as a
// single line. Strips newlines and other control characters before
// anything reaches the clipboard.
function clipboardSafeText(value) {
  return String(value === null || value === undefined ? "" : value).replace(/[\r\n\x00-\x1f]/g, "")
}

// No example paths: unlike a timezone list, project paths are inherently
// personal, so there is no sane default. An empty config renders as
// "no projects configured" in the panel rather than auditing nothing
// silently.
function defaultProjects() {
  return []
}

// Single source of truth for "what does this plugin actually cover" —
// used both for the panel's own always-visible caption and (kept manually
// in sync) manifest.json's description, since the marketplace catalog
// displays that description as the first thing a browsing user sees.
var SUPPORTED_ECOSYSTEMS = ["npm", "pnpm", "yarn", "cargo", "pip", "Go", "Ruby", ".NET"]

function supportedEcosystemsText() {
  return "Supports: " + SUPPORTED_ECOSYSTEMS.join(" · ")
}

// Builds one bash script that, for each configured project, detects its
// package manager by manifest file, checks the matching audit tool is on
// PATH, and runs it. Detection follows NOTES.md's mapping: package.json ->
// npm, Cargo.toml -> cargo, requirements.txt/pyproject.toml -> pip, plus
// go.mod -> govulncheck. A repo with more than one manifest picks
// Cargo.toml > package.json > Python > go.mod, an arbitrary but stable
// order.
//
// Every audit tool exits non-zero when it *finds* vulnerabilities (that's
// the normal, common case) — so unlike a "|| fallback" pattern, tool-missing
// detection has to happen before invocation via `command -v`, never by
// reacting to the audit command's own exit code.
// One marker echo, tagging which manager a branch is about to run (or
// "missing:<tool>" / "unknown" when there's nothing to run).
function markerEcho(index, manager) {
  return "echo " + shellQuote(REPO_MARKER + index + "|" + manager)
}

// Bar/shell processes on Omarchy run under a systemd/PAM-managed session
// whose PATH is fixed at session start — NOT the interactive-shell PATH a
// terminal gets. Installers for per-user toolchains (rustup's `.cargo/env`,
// nvm, etc.) typically only append to shell rc files (.bashrc/.profile),
// which a non-login process like this one never sources, and restarting
// the shell does not re-derive the session's PATH either (verified: a
// rustup-installed `cargo-audit` stayed invisible to a live widget across
// an `omarchy restart shell`, while the very same binary was on PATH in a
// terminal). Prepending common per-user toolchain bin dirs here means a
// freshly-installed audit tool works without requiring a full logout/login
// — cheap and harmless even when a given directory doesn't exist.
//
// Also creates the plugin's own state directory (ignored findings,
// last-seen finding ids for new-finding notifications — see Panel.qml's
// stateFile). This runs before every generated script, bulk or per-project,
// so the directory is guaranteed to exist by the time anything could
// possibly try to write into it — a QML FileView can't create missing
// parent directories itself, and the alternative (an async execDetached
// "mkdir -p" fired right before the first write) would race that write on
// a fresh install. `mkdir -p` is idempotent, so re-running it every scan is
// harmless.
var STATE_DIR = "$HOME/.local/state/omarchy-depaudit"
var PATH_PREFIX = "export PATH=\"$HOME/.cargo/bin:$HOME/go/bin:$HOME/.local/bin:"
  + "$HOME/.local/share/mise/shims:$HOME/.dotnet:$PATH\"; mkdir -p " + STATE_DIR + "; "

function buildAuditScript(projects) {
  var parts = []
  for (var i = 0; i < projects.length; i++) {
    var path = String(projects[i].path || "")
    if (path === "") continue
    // findSafePath: qPath is used as a bare `find`/`cd` argument below
    // (the .NET detection branch's `find $qPath -maxdepth 1 ...` in
    // particular) — see findSafePath's own comment for why an
    // unprefixed dash-leading path is dangerous there specifically.
    var qPath = shellQuote(findSafePath(path))

    parts.push(
      // Checked before anything else: every branch below assumes the path
      // exists and just tests for a manifest file inside it. A path that
      // doesn't exist at all (typo, moved/deleted project, unmounted drive)
      // would otherwise silently fall through every `[ -f ]` check and land
      // in "no recognized manifest" — a misleading answer, since the real
      // problem is the path itself, not what's (or isn't) in it.
      "if [ ! -d " + qPath + " ]; then " + markerEcho(i, "missing-path") + ";" +
      "elif [ -f " + qPath + "/Cargo.toml ]; then" +
      " if command -v cargo-audit >/dev/null 2>&1; then" +
      "  " + markerEcho(i, "cargo") + ";" +
      "  (cd " + qPath + " && cargo audit --json 2>/dev/null);" +
      " else " + markerEcho(i, "missing:cargo-audit") + "; fi;" +
      // Lockfile decides which of the three JS package managers actually
      // resolved this tree — a pnpm/yarn project audited with plain `npm
      // audit` can resolve a different dependency tree than what's really
      // installed. pnpm's JSON is npm's *legacy* per-advisory-id schema
      // (verified against a real pnpm 11.24 run — different from npm 7+'s
      // per-package schema handled elsewhere); yarn classic's `--json` is
      // newline-delimited JSON (one object per line), not one document.
      "elif [ -f " + qPath + "/package.json ]; then" +
      " if [ -f " + qPath + "/pnpm-lock.yaml ]; then" +
      "  if command -v pnpm >/dev/null 2>&1; then" +
      "   " + markerEcho(i, "pnpm") + ";" +
      "   (cd " + qPath + " && pnpm audit --json 2>/dev/null);" +
      "  else " + markerEcho(i, "missing:pnpm") + "; fi;" +
      " elif [ -f " + qPath + "/yarn.lock ]; then" +
      "  if command -v yarn >/dev/null 2>&1; then" +
      "   " + markerEcho(i, "yarn") + ";" +
      "   (cd " + qPath + " && yarn audit --json 2>/dev/null);" +
      "  else " + markerEcho(i, "missing:yarn") + "; fi;" +
      " else" +
      "  if command -v npm >/dev/null 2>&1; then" +
      "   " + markerEcho(i, "npm") + ";" +
      "   (cd " + qPath + " && npm audit --json 2>/dev/null);" +
      "  else " + markerEcho(i, "missing:npm") + "; fi;" +
      " fi;" +
      // `-r requirements.txt` / the project_path positional are required:
      // bare `pip-audit` with no target audits pip-audit's OWN Python
      // environment, not the repo being checked.
      "elif [ -f " + qPath + "/requirements.txt ]; then" +
      " if command -v pip-audit >/dev/null 2>&1; then" +
      "  " + markerEcho(i, "pip") + ";" +
      "  (cd " + qPath + " && pip-audit --format json -r requirements.txt 2>/dev/null);" +
      " else " + markerEcho(i, "missing:pip-audit") + "; fi;" +
      "elif [ -f " + qPath + "/pyproject.toml ]; then" +
      " if command -v pip-audit >/dev/null 2>&1; then" +
      "  " + markerEcho(i, "pip") + ";" +
      "  (cd " + qPath + " && pip-audit --format json . 2>/dev/null);" +
      " else " + markerEcho(i, "missing:pip-audit") + "; fi;" +
      // `-scan module` checks every declared dependency's version against
      // the vuln DB regardless of whether the code actually calls into the
      // vulnerable function — matching npm/cargo/pip audit's semantics
      // (declared-dependency staleness), not govulncheck's default
      // call-graph-reachability mode.
      "elif [ -f " + qPath + "/go.mod ]; then" +
      " if command -v govulncheck >/dev/null 2>&1; then" +
      "  " + markerEcho(i, "go") + ";" +
      "  (cd " + qPath + " && govulncheck -scan module -json 2>/dev/null);" +
      " else " + markerEcho(i, "missing:govulncheck") + "; fi;" +
      // Gemfile.lock, not bare Gemfile: bundle-audit only reads an already-
      // resolved lockfile, it doesn't generate one — a repo with just a
      // Gemfile (no committed lock) isn't something we can silently mutate
      // by running `bundle lock` on the user's behalf.
      "elif [ -f " + qPath + "/Gemfile.lock ]; then" +
      " if command -v bundle-audit >/dev/null 2>&1; then" +
      "  " + markerEcho(i, "ruby") + ";" +
      "  (cd " + qPath + " && bundle-audit check --format json 2>/dev/null);" +
      " else " + markerEcho(i, "missing:bundler-audit") + "; fi;" +
      // No single manifest filename for .NET (*.csproj / *.sln / *.fsproj
      // all count), so detection is a glob find rather than `[ -f ]`.
      // `dotnet list package --vulnerable` is a built-in dotnet CLI
      // subcommand, not a separate installable tool — the "missing tool"
      // branch here means the `dotnet` SDK itself isn't on PATH.
      "elif [ -n \"$(find " + qPath + " -maxdepth 1 \\( -name '*.csproj' -o -name '*.sln' -o -name '*.fsproj' \\) -print -quit 2>/dev/null)\" ]; then" +
      " if command -v dotnet >/dev/null 2>&1; then" +
      "  " + markerEcho(i, "dotnet") + ";" +
      "  (cd " + qPath + " && dotnet list package --vulnerable --include-transitive --format json 2>/dev/null);" +
      " else " + markerEcho(i, "missing:dotnet") + "; fi;" +
      "else " + markerEcho(i, "unknown") + "; fi"
    )
  }
  return PATH_PREFIX + parts.join("; echo; ")
}

// Splits the combined probe output back into one block per repo and hands
// each block's JSON payload to the manager-specific parser. Blocks are
// keyed by project index (see buildAuditScript) rather than by path/label
// text, so those free-form config strings never need parsing back out of
// the shell's stdout.
function parseAuditOutput(raw, projects) {
  var text = String(raw || "")
  // Anchored to the exact marker-line shape `markerEcho` produces
  // (MARKER<index>|<manager>\n), not just the bare marker substring —
  // a plain text.split(REPO_MARKER) would desync every chunk boundary
  // after it if any tool's own output (an advisory title, a package
  // description) ever happened to contain the literal marker text.
  // Requiring the immediate `\d+|...\n` structure makes that
  // indistinguishable-by-accident.
  var markerLine = new RegExp(REPO_MARKER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(\\d+)\\|([^\\n]*)\\n", "g")
  var matches = []
  var m
  while ((m = markerLine.exec(text)) !== null) {
    matches.push({ index: parseInt(m[1], 10), manager: m[2], bodyStart: markerLine.lastIndex, matchStart: m.index })
  }

  var byIndex = {}
  for (var i = 0; i < matches.length; i++) {
    var bodyEnd = (i + 1 < matches.length) ? matches[i + 1].matchStart : text.length
    var body = text.substring(matches[i].bodyStart, bodyEnd)
    var index = matches[i].index
    if (isNaN(index) || !projects[index]) continue
    byIndex[index] = parseRepoBlock(projects[index].label || projects[index].path, projects[index].path, matches[i].manager, body)
  }

  var results = []
  for (var p = 0; p < projects.length; p++) {
    var project = projects[p]
    results.push(byIndex[p] || {
      label: plainText(project.label || project.path || ""),
      path: String(project.path || ""),
      manager: "pending",
      status: "pending",
      findings: [],
      worstSeverity: "none"
    })
  }
  return results
}

// Builds the list to show *while* a scan is in flight: a project already
// present in existingRepos (by path) keeps its most recent real result;
// anything newly configured/discovered that hasn't been scanned yet gets
// the same "pending" placeholder parseAuditOutput itself falls back to
// for a project whose marker never showed up in the script's output. Lets
// the project list appear immediately on open/refresh instead of staying
// blank (first run) or stale (re-run) until the whole — possibly slow —
// audit script finishes.
function buildPendingRepos(projects, existingRepos) {
  var byPath = {}
  for (var i = 0; i < existingRepos.length; i++) byPath[existingRepos[i].path] = existingRepos[i]
  var out = []
  for (var j = 0; j < projects.length; j++) {
    var p = projects[j]
    out.push(byPath[p.path] || {
      label: plainText(p.label || p.path || ""),
      path: String(p.path || ""),
      manager: "pending",
      status: "pending",
      findings: [],
      worstSeverity: "none"
    })
  }
  return out
}

// Hard cap on how much stdout a single generated script's process may
// accumulate before Panel.qml kills it — StdioCollector has no built-in
// limit of its own, and a malicious project (or a compromised registry/
// advisory response one of the real audit tools fetches) could otherwise
// make the shell retain and try to parse an arbitrarily large result,
// exhausting memory. Calibrated against real data, not a guess: a real
// (legitimate, non-malicious) large yarn monorepo audited during this
// project's own development produced 30.4 MB of raw output — a cap set
// too low would break real large repos, not just stop hostile ones. 100
// MiB leaves that real case more than 3x headroom while still bounding
// worst-case memory to something finite.
var MAX_COLLECTED_BYTES = 100 * 1024 * 1024

// Repo list to show when a script's output was killed for exceeding
// MAX_COLLECTED_BYTES — every project that was part of that run reports a
// bounded, honest error instead of the shell silently keeping stale data
// or attempting to parse a truncated/garbage result.
function buildOversizedOutputRepos(projects) {
  var out = []
  for (var i = 0; i < projects.length; i++) {
    var p = projects[i]
    out.push({
      label: plainText(p.label || p.path || ""),
      path: String(p.path || ""),
      manager: "error",
      status: "output-too-large",
      findings: [],
      worstSeverity: "none"
    })
  }
  return out
}

function parseRepoBlock(label, path, manager, body) {
  var base = { label: plainText(label), path: path, manager: manager }

  if (manager === "missing-path") {
    return Object.assign(base, { status: "missing-path", findings: [], worstSeverity: "none" })
  }
  if (manager.indexOf("missing:") === 0) {
    return Object.assign(base, {
      status: "missing-tool",
      tool: manager.substring("missing:".length),
      findings: [],
      worstSeverity: "none"
    })
  }
  if (manager === "unknown") {
    return Object.assign(base, { status: "unrecognized", findings: [], worstSeverity: "none" })
  }

  // govulncheck's `-json` and yarn classic's `audit --json` are both NOT a
  // single JSON document — govulncheck concatenates top-level values with
  // no separator, yarn newline-delimits one object per line — so both are
  // parsed straight from the raw text rather than through the single
  // JSON.parse the other managers use.
  //
  // The whole dispatch below (JSON.parse included) is wrapped in one
  // try/catch: JSON.parse failing was already handled, but every
  // individual parseXAudit function assumes its ecosystem's normal shape
  // and reads straight into nested fields — a real tool emitting a
  // schema variant we haven't seen (a null entry where an object was
  // expected, a missing array) would throw a TypeError instead of just
  // failing to find any findings. Uncaught, that would propagate out of
  // parseAuditOutput entirely and abort parsing every *other* repo in the
  // same batch too, not just this one. One bad/unexpected response
  // degrades to a single "parse-error" repo instead.
  var findings
  try {
    if (manager === "go") {
      findings = parseGoAudit(body)
    } else if (manager === "yarn") {
      findings = parseYarnAudit(body)
    } else {
      var json = JSON.parse(body)
      if (manager === "npm") findings = parseNpmAudit(json)
      else if (manager === "pnpm") findings = parsePnpmAudit(json)
      else if (manager === "cargo") findings = parseCargoAudit(json)
      else if (manager === "pip") findings = parsePipAudit(json)
      else if (manager === "ruby") findings = parseRubyAudit(json)
      else if (manager === "dotnet") findings = parseDotnetAudit(json)
      else findings = []
    }
  } catch (e) {
    return Object.assign(base, { status: "parse-error", findings: [], worstSeverity: "none" })
  }

  return Object.assign(base, {
    status: "ok",
    findings: findings,
    worstSeverity: worstOf(findings)
  })
}

var SEVERITY_RANK = { critical: 4, high: 3, moderate: 2, low: 1, unknown: 0, none: -1 }

function worstOf(findings) {
  var worst = "none"
  for (var i = 0; i < findings.length; i++) {
    if (SEVERITY_RANK[findings[i].severity] > SEVERITY_RANK[worst]) worst = findings[i].severity
  }
  return worst
}

// Advisory aliases (RustSec/OSV/pip-audit/govulncheck all carry an
// `aliases` array) list every cross-reference — CVE, GHSA, etc. — in no
// guaranteed order. Not every advisory has a CVE assigned, so this is a
// preference, not a guarantee: prefer a CVE id for display since it's the
// one identifier readers universally recognize, fall back to whatever the
// native source id already is otherwise.
function pickCveAlias(aliases) {
  if (!Array.isArray(aliases)) return null
  for (var i = 0; i < aliases.length; i++) {
    if (/^CVE-\d{4}-\d+$/i.test(String(aliases[i]))) return aliases[i]
  }
  return null
}

// npm audit --json (npm 7+): top-level `vulnerabilities` keyed by package
// name, each with severity, range, fixAvailable (object | true | false),
// and `via` entries that are either dependency-name strings (a transitive
// path segment, not an advisory) or advisory objects carrying title/url.
// A package can be flagged by more than one *distinct* GHSA advisory at
// once (verified against a real npm audit run: minimist matched both
// GHSA-vh95-rmgr-6w4m at moderate and GHSA-xvch-5gv4-984h at critical) —
// earlier code kept only the first `via` object and silently dropped the
// rest, undercounting real findings. Emits one finding per advisory object
// instead. npm's JSON carries no `aliases`/CVE field at all, only a GHSA
// URL, so `id` here is the GHSA slug pulled from that URL.
function parseNpmAudit(json) {
  var out = []
  var vulns = (json && json.vulnerabilities) || {}
  for (var name in vulns) {
    var v = vulns[name]
    var fixedVersion = (v.fixAvailable && typeof v.fixAvailable === "object") ? v.fixAvailable.version : null
    var fixCommand = fixedVersion ? ("npm install " + name + "@" + fixedVersion) : "npm audit fix"
    var advisories = Array.isArray(v.via) ? v.via.filter(function(entry) { return entry && typeof entry === "object" }) : []
    for (var i = 0; i < advisories.length; i++) {
      var advisory = advisories[i]
      var url = advisory.url || ""
      var slug = url.substring(url.lastIndexOf("/") + 1)
      out.push({
        package: name,
        severity: normalizeSeverity(advisory.severity || v.severity),
        range: advisory.range || v.range || "",
        fixedVersion: fixedVersion,
        id: slug,
        title: advisory.title || "",
        url: url,
        fixCommand: fixCommand
      })
    }
  }
  return out
}

// pnpm audit --json: NOT npm 7+'s per-package `vulnerabilities` schema —
// pnpm uses the older npm-legacy shape, `{advisories: {"<numericId>":
// {module_name, severity, title, github_advisory_id, url,
// patched_versions, findings: [{version, ...}]}}}` (verified against a
// real pnpm 11.24 run). pnpm's severity is real (moderate/critical, etc.),
// no scoring needed. `patched_versions` is a range like cargo's, not an
// exact version, so the fix command stays a generic `pnpm update <pkg>`.
function parsePnpmAudit(json) {
  var out = []
  var advisories = (json && json.advisories) || {}
  for (var key in advisories) {
    var a = advisories[key]
    var findingRows = Array.isArray(a.findings) ? a.findings : []
    var version = findingRows.length > 0 ? findingRows[0].version : ""
    out.push({
      package: a.module_name || "",
      severity: normalizeSeverity(a.severity),
      range: version,
      fixedVersion: a.patched_versions || null,
      id: a.github_advisory_id || (a.id !== undefined ? String(a.id) : ""),
      title: a.title || "",
      url: a.url || "",
      fixCommand: "pnpm update " + (a.module_name || "")
    })
  }
  return out
}

// yarn (classic 1.x) audit --json: newline-delimited JSON, one
// `{type, data}` object per line — verified against a real yarn 1.22 run.
// Only `type: "auditAdvisory"` lines are per-package findings; the rest
// (`auditSummary`, etc.) are skipped. Richer than pnpm's/npm's shape: a
// real `cves` array (pickCveAlias-preferred over the GHSA id) and even a
// CVSS vector, though the vector isn't scored here since `severity` is
// already given directly. `patched_versions` is a range, same generic
// `yarn upgrade <pkg>` fix command as pnpm/cargo.
function parseYarnAudit(rawText) {
  var out = []
  var seenAdvisoryIds = {}
  var lines = String(rawText || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (line === "") continue
    var obj
    try { obj = JSON.parse(line) } catch (e) { continue }
    if (obj.type !== "auditAdvisory") continue
    var a = (obj.data && obj.data.advisory) || {}
    // yarn classic emits one auditAdvisory event per dependency PATH that
    // reaches the vulnerable package, not per distinct vulnerability — in
    // a large workspace where many members depend (transitively) on the
    // same package, the exact same advisory repeats once per path. Found
    // live in a real ~3000-finding repo: a single `tar` CVE alone showed
    // up dozens of times in a row, identical severity/version/fix, because
    // that many workspace members happened to pull it in. advisory.id is
    // yarn's own stable numeric id for the underlying advisory record
    // (distinct from `resolution.id`/path, which does vary per
    // occurrence), so it's the right dedup key — two genuinely different
    // advisories for the same package (this file's own fixture: minimist
    // has two separate real CVEs, ids 1096466 and 1097677) keep distinct
    // ids and both still get reported.
    var advisoryId = a.id
    if (advisoryId !== undefined && advisoryId !== null) {
      if (seenAdvisoryIds[advisoryId]) continue
      seenAdvisoryIds[advisoryId] = true
    }
    var findingRows = Array.isArray(a.findings) ? a.findings : []
    var version = findingRows.length > 0 ? findingRows[0].version : ""
    out.push({
      package: a.module_name || "",
      severity: normalizeSeverity(a.severity),
      range: version,
      fixedVersion: a.patched_versions || null,
      id: pickCveAlias(a.cves) || a.github_advisory_id || "",
      title: a.title || "",
      url: a.url || "",
      fixCommand: "yarn upgrade " + (a.module_name || "")
    })
  }
  return out
}

// cargo-audit --json: `vulnerabilities.list[]`, each with `advisory`
// (id/title/url) and `package` (name/version); patched versions live under
// `versions.patched`. RustSec advisories carry no plain `severity` field,
// but do carry a CVSS v3.x vector string at `advisory.cvss` when scored
// (verified against a real cargo-audit 0.22.2 run: RUSTSEC-2020-0071 —
// cvssBaseSeverity resolves its vector to 6.2, matching that CVE's
// published NVD score of 6.2 MEDIUM). Only bucketed "unknown" when no CVSS
// vector is present at all (e.g. "unmaintained" notices).
function parseCargoAudit(json) {
  var out = []
  var list = (json && json.vulnerabilities && json.vulnerabilities.list) || []
  for (var i = 0; i < list.length; i++) {
    var entry = list[i]
    var advisory = entry.advisory || {}
    var pkg = entry.package || {}
    // `versions.patched` entries are semver *requirement ranges* (e.g.
    // ">=0.2.23"), not exact versions — `cargo update --precise` demands an
    // exact version, so a range there would generate a fix command that
    // fails to run. Plain `cargo update -p <pkg>` (bump within whatever
    // Cargo.toml already allows) is the only command guaranteed valid; the
    // range is shown for reference only.
    var patched = (entry.versions && entry.versions.patched) || []
    out.push({
      package: pkg.name || "",
      severity: advisory.severity ? normalizeSeverity(advisory.severity)
        : (advisory.cvss ? cvssBaseSeverity(advisory.cvss) : "unknown"),
      range: pkg.version || "",
      fixedVersion: patched.length > 0 ? patched[0] : null,
      id: pickCveAlias(advisory.aliases) || advisory.id || "",
      title: advisory.title || "",
      // RustSec's own advisory page (verified live: rustsec.org/advisories/
      // RUSTSEC-2020-0071.html resolves), not `advisory.url` — that field is
      // whatever external reference the advisory's author happened to pick,
      // often just a GitHub issue thread on the affected package's repo
      // rather than a page about the finding itself. pip/go's `url` already
      // point at their own database's dedicated page (osv.dev, pkg.go.dev);
      // this makes cargo consistent with them.
      url: advisory.id ? ("https://rustsec.org/advisories/" + advisory.id + ".html") : (advisory.url || ""),
      fixCommand: "cargo update -p " + (pkg.name || "")
    })
  }
  return out
}

// Standard CVSS v3.1 base-metric weights (First.org spec).
var CVSS31_WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { N: 0, L: 0.22, H: 0.56 }
}

// CVSS spec's Roundup(): round a score up to the nearest 0.1.
function cvssRoundup(input) {
  var intInput = Math.round(input * 100000)
  if (intInput % 10000 === 0) return intInput / 100000
  return (Math.floor(intInput / 10000) + 1) / 10
}

// Computes a CVSS v3.x base score from a vector string (e.g.
// "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") and buckets it using the
// standard NVD qualitative ranges (9.0+ critical, 7.0+ high, 4.0+ moderate,
// >0 low) — the same critical/high/moderate/low scale npm's advisories use.
// Returns "unknown" for a missing/malformed vector. Cargo is the only one
// of the four tools whose advisories carry a CVSS vector as of this
// writing, but this takes a bare vector string so it's reusable if pip/go's
// OSV sources ever start populating one too.
function cvssBaseSeverity(vector) {
  var parts = String(vector || "").split("/")
  var m = {}
  for (var i = 0; i < parts.length; i++) {
    var kv = parts[i].split(":")
    if (kv.length === 2) m[kv[0]] = kv[1]
  }
  var av = CVSS31_WEIGHTS.AV[m.AV]
  var ac = CVSS31_WEIGHTS.AC[m.AC]
  var ui = CVSS31_WEIGHTS.UI[m.UI]
  var scope = m.S
  var pr = scope === "C" ? CVSS31_WEIGHTS.PR_C[m.PR] : CVSS31_WEIGHTS.PR_U[m.PR]
  var c = CVSS31_WEIGHTS.CIA[m.C]
  var iImpact = CVSS31_WEIGHTS.CIA[m.I]
  var a = CVSS31_WEIGHTS.CIA[m.A]
  if (av === undefined || ac === undefined || pr === undefined || ui === undefined
    || c === undefined || iImpact === undefined || a === undefined) return "unknown"

  var iss = 1 - ((1 - c) * (1 - iImpact) * (1 - a))
  var impact = scope === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
  var exploitability = 8.22 * av * ac * pr * ui
  var score = 0
  if (impact > 0) {
    score = scope === "U"
      ? cvssRoundup(Math.min(impact + exploitability, 10))
      : cvssRoundup(Math.min(1.08 * (impact + exploitability), 10))
  }

  if (score >= 9.0) return "critical"
  if (score >= 7.0) return "high"
  if (score >= 4.0) return "moderate"
  if (score > 0) return "low"
  return "unknown"
}

// pip-audit --format json: `{dependencies: [{name, version, vulns: [...]}],
// fixes: [...]}` — NOT a bare top-level array (verified against a real
// pip-audit 2.10.1 run; earlier code here assumed the bare-array shape and
// silently found zero findings on every real invocation). OSV-sourced vulns
// carry no severity field either — same "unknown" bucket as cargo, for the
// same reason.
function parsePipAudit(json) {
  var out = []
  var packages = (json && Array.isArray(json.dependencies)) ? json.dependencies : []
  for (var i = 0; i < packages.length; i++) {
    var pkg = packages[i]
    var vulns = pkg.vulns || []
    for (var j = 0; j < vulns.length; j++) {
      var vuln = vulns[j]
      var fixes = vuln.fix_versions || []
      // pip-audit gives no short human title/summary field (only `id` and
      // a paragraph-length `description`, too long for an inline row), so
      // `title` stays empty here — the id (CVE-preferred) is the label.
      out.push({
        package: pkg.name || "",
        severity: "unknown",
        range: pkg.version || "",
        fixedVersion: fixes.length > 0 ? fixes[0] : null,
        id: pickCveAlias(vuln.aliases) || vuln.id || "",
        title: "",
        url: vuln.id ? ("https://osv.dev/vulnerability/" + vuln.id) : "",
        fixCommand: fixes.length > 0
          ? ("pip install " + (pkg.name || "") + "==" + fixes[0])
          : ("pip install --upgrade " + (pkg.name || ""))
      })
    }
  }
  return out
}

// govulncheck's `-json` output is a sequence of concatenated top-level JSON
// values — {"config":...}{"progress":...}{"osv":...}{"finding":...}... —
// not one JSON document and not newline-delimited, so JSON.parse can't
// touch it directly. This walks the text tracking string/escape state and
// brace depth to split it back into individual objects (verified against a
// real govulncheck 1.7.0 run), then JSON.parse's each one.
function parseJsonStream(text) {
  var objects = []
  var depth = 0
  var start = -1
  var inString = false
  var escape = false
  var str = String(text || "")
  for (var i = 0; i < str.length; i++) {
    var ch = str.charAt(i)
    if (inString) {
      if (escape) escape = false
      else if (ch === "\\") escape = true
      else if (ch === '"') inString = false
      continue
    }
    if (ch === '"') { inString = true; continue }
    if (ch === "{") {
      if (depth === 0) start = i
      depth++
    } else if (ch === "}") {
      // Clamped at 0 rather than going negative: a stray unmatched "}"
      // before any real object (stray warning text on stdout, say) would
      // otherwise desync depth permanently — every *later*, genuinely
      // well-formed object's matching "}" would land on some depth other
      // than 0, so the `depth === 0` check below would never fire again
      // and every remaining object in the stream would be silently
      // dropped, not just the one after the stray brace.
      if (depth > 0) {
        depth--
        if (depth === 0 && start !== -1) {
          try { objects.push(JSON.parse(str.substring(start, i + 1))) } catch (e) { /* skip malformed chunk */ }
          start = -1
        }
      }
    }
  }
  return objects
}

// govulncheck -scan module -json: findings come as {finding: {osv, fixed_
// version, trace: [{module, version}]}} objects, cross-referenced against
// {osv: {id, summary, database_specific: {url}}} objects carrying the OSV
// records govulncheck consulted (only some of which matched — non-matches
// are not filtered out of the stream, so results are built strictly from
// `finding` entries, using the `osv` map only to enrich them). Like cargo
// and pip, the Go vulnerability DB carries no severity field, so these are
// bucketed "unknown" too. Unlike cargo's range-only `versions.patched`,
// govulncheck's `fixed_version` is a single exact version, so `go get
// module@fixed_version` is a precise, always-valid fix command.
function parseGoAudit(rawText) {
  var objects = parseJsonStream(rawText)
  var osvById = {}
  var findings = []
  for (var i = 0; i < objects.length; i++) {
    var obj = objects[i]
    if (obj.osv && obj.osv.id) osvById[obj.osv.id] = obj.osv
    else if (obj.finding) findings.push(obj.finding)
  }

  var out = []
  for (var f = 0; f < findings.length; f++) {
    var finding = findings[f]
    var osv = osvById[finding.osv] || {}
    var trace = (finding.trace && finding.trace[0]) || {}
    var pkg = trace.module || ""
    var fixed = finding.fixed_version || null
    out.push({
      package: pkg,
      severity: "unknown",
      range: trace.version || "",
      fixedVersion: fixed,
      id: pickCveAlias(osv.aliases) || finding.osv || "",
      title: osv.summary || "",
      url: (osv.database_specific && osv.database_specific.url) || (finding.osv ? ("https://pkg.go.dev/vuln/" + finding.osv) : ""),
      fixCommand: fixed ? ("go get " + pkg + "@" + fixed) : ("go get -u " + pkg)
    })
  }
  return out
}

// bundle-audit --format json: {version, created_at, results: [{type, gem:
// {name, version}, advisory: {id, url, title, cve, ghsa, patched_versions,
// criticality}}]}. Unlike cargo/pip/go, ruby-advisory-db carries a real
// severity out of the box — `advisory.criticality` is low/medium/high/
// critical (verified against a real bundler-audit 0.9.3 run; some
// advisories have it null, bucketed "unknown" same as elsewhere). `id` is
// already the advisory's own identifier, a CVE when one was assigned.
// `patched_versions` are ranges like cargo's `versions.patched`, not exact
// versions, so the fix command stays a generic `bundle update <gem>`.
// Result entries can have `type` other than "unpatched_gem" (e.g. an
// insecure Gemfile source) — those aren't per-package findings in this
// shape and are skipped rather than guessed at.
function parseRubyAudit(json) {
  var out = []
  var results = (json && Array.isArray(json.results)) ? json.results : []
  for (var i = 0; i < results.length; i++) {
    var entry = results[i]
    if (entry.type !== "unpatched_gem") continue
    var gem = entry.gem || {}
    var advisory = entry.advisory || {}
    var patched = Array.isArray(advisory.patched_versions) ? advisory.patched_versions : []
    out.push({
      package: gem.name || "",
      severity: advisory.criticality ? normalizeSeverity(advisory.criticality) : "unknown",
      range: gem.version || "",
      fixedVersion: patched.length > 0 ? patched[0] : null,
      id: advisory.id || "",
      title: advisory.title || "",
      // RubySec's own advisory page (verified live: rubysec.com/advisories/
      // CVE-2020-8161/ resolves) — advisory.url is, like cargo's, whatever
      // external reference the advisory author picked (often a mailing-list
      // thread), not a dedicated finding page.
      url: advisory.id ? ("https://rubysec.com/advisories/" + advisory.id + "/") : (advisory.url || ""),
      fixCommand: "bundle update " + (gem.name || "")
    })
  }
  return out
}

// dotnet list package --vulnerable --include-transitive --format json:
// {projects: [{path, frameworks: [{framework, topLevelPackages: [...],
// transitivePackages: [...]}]}]}. Each package entry carries
// `vulnerabilities: [{severity, advisoryurl}]` (Critical/High/Moderate/Low,
// capitalized — normalizeSeverity lowercases before matching). Sparser than
// every other tool here: no CVE field and no fixed-version info at all,
// just the current version and a GHSA advisory URL, so `id` is the GHSA
// slug pulled from that URL and the fix command is a generic re-add
// (`dotnet add package <id>`, which resolves to latest stable) rather than
// a specific pin. `transitivePackages` is inferred from the CLI's naming
// convention (parallel to `topLevelPackages`) — not exercised by a live
// vulnerable-transitive-dependency example in testing, only topLevelPackages
// was.
function parseDotnetAudit(json) {
  var out = []
  var seenPackageAdvisory = {}
  var projects = (json && Array.isArray(json.projects)) ? json.projects : []
  for (var p = 0; p < projects.length; p++) {
    var frameworks = Array.isArray(projects[p].frameworks) ? projects[p].frameworks : []
    for (var f = 0; f < frameworks.length; f++) {
      var top = Array.isArray(frameworks[f].topLevelPackages) ? frameworks[f].topLevelPackages : []
      var transitive = Array.isArray(frameworks[f].transitivePackages) ? frameworks[f].transitivePackages : []
      var packages = top.concat(transitive)
      for (var g = 0; g < packages.length; g++) {
        var pkg = packages[g]
        var vulns = Array.isArray(pkg.vulnerabilities) ? pkg.vulnerabilities : []
        for (var v = 0; v < vulns.length; v++) {
          var vuln = vulns[v]
          var url = vuln.advisoryurl || ""
          var slug = url.substring(url.lastIndexOf("/") + 1)
          // `dotnet list package --vulnerable` at a .sln reports results
          // PER PROJECT the solution contains — the same shared transitive
          // package (very common in a real multi-project solution: several
          // projects all referencing the same logging/serialization
          // package) repeats once per project that references it. Same
          // duplication shape as yarn classic's per-path repeats (see
          // parseYarnAudit) — proven with a synthetic 2-project solution
          // sharing one vulnerable package before this fix (2 findings
          // instead of 1). Dedupe key is package+advisory since dotnet's
          // JSON carries no separate stable advisory id the way yarn's
          // does.
          var dedupeKey = (pkg.id || "") + "|" + slug
          if (seenPackageAdvisory[dedupeKey]) continue
          seenPackageAdvisory[dedupeKey] = true
          out.push({
            package: pkg.id || "",
            severity: normalizeSeverity(vuln.severity),
            range: pkg.resolvedVersion || pkg.requestedVersion || "",
            fixedVersion: null,
            id: slug,
            title: "",
            url: url,
            fixCommand: "dotnet add package " + (pkg.id || "")
          })
        }
      }
    }
  }
  return out
}

function normalizeSeverity(value) {
  var s = String(value || "").toLowerCase()
  if (s === "critical" || s === "high" || s === "moderate" || s === "low") return s
  if (s === "medium") return "moderate"
  return "unknown"
}

// Worst severity across every repo, for the bar badge.
function aggregate(repos) {
  var total = 0
  var worst = "none"
  for (var i = 0; i < repos.length; i++) {
    var findings = repos[i].findings || []
    total += findings.length
    if (SEVERITY_RANK[repos[i].worstSeverity] > SEVERITY_RANK[worst]) worst = repos[i].worstSeverity
  }
  return { total: total, worstSeverity: worst }
}

// Per-severity finding count — the collapsed-section summary (e.g.
// "2 critical  1 high") so a project doesn't need to be opened just to see
// whether it's a problem, and the detail view's filter chip counts.
function countBySeverity(findings) {
  var counts = { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 }
  for (var i = 0; i < findings.length; i++) {
    var s = findings[i].severity
    if (counts[s] !== undefined) counts[s]++
  }
  return counts
}

// Every severity a repo's detail view can be filtered to, in display order
// — "all" first, then worst to least severe.
var SEVERITY_FILTERS = ["all", "critical", "high", "moderate", "low", "unknown"]

// Findings for one repo's detail view, filtered to a single severity —
// "all"/empty returns every finding unfiltered.
function filterFindings(findings, severity) {
  if (!severity || severity === "all") return findings.slice()
  var out = []
  for (var i = 0; i < findings.length; i++) {
    if (findings[i].severity === severity) out.push(findings[i])
  }
  return out
}

// Slices an already-filtered findings list into one page. Clamps the
// requested page into range so switching to a smaller filter (fewer pages)
// while sitting on a now out-of-range page returns the last valid page
// instead of an empty one.
function paginateFindings(findings, page, pageSize) {
  var size = Math.max(1, pageSize | 0)
  var pageCount = Math.max(1, Math.ceil(findings.length / size))
  var p = Math.min(Math.max(0, page | 0), pageCount - 1)
  var start = p * size
  return {
    items: findings.slice(start, start + size),
    page: p,
    pageCount: pageCount,
    total: findings.length
  }
}

// ---- In-panel settings form -------------------------------------------
//
// The panel's settings view edits `projects`/`discoverRoots` as plain
// multi-line text (one entry per line) rather than a dynamic per-row
// add/remove list widget — far less QML to get right, and it's copy-paste
// friendly. These pure functions do the two-way conversion so the QML side
// only ever handles strings.

// "label | path" or just "path" (label optional, defaults to the
// directory's basename same as discovery does) per line. Blank lines
// ignored. A line with a "|" but nothing after it is dropped — an empty
// path is not a usable project entry.
function parseProjectsText(text) {
  var lines = String(text || "").split("\n")
  var out = []
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (line === "") continue
    var pipeIdx = line.indexOf("|")
    if (pipeIdx === -1) {
      out.push({ path: line })
      continue
    }
    var label = line.substring(0, pipeIdx).trim()
    var path = line.substring(pipeIdx + 1).trim()
    if (path === "") continue
    out.push(label === "" ? { path: path } : { label: label, path: path })
  }
  return out
}

function projectsToText(projects) {
  var lines = []
  for (var i = 0; i < (projects || []).length; i++) {
    var p = projects[i]
    lines.push(p.label ? (p.label + " | " + p.path) : p.path)
  }
  return lines.join("\n")
}

// One absolute path per line, blank lines ignored.
function parseRootsText(text) {
  var lines = String(text || "").split("\n")
  var out = []
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (line !== "") out.push(line)
  }
  return out
}

function rootsToText(roots) {
  return (roots || []).join("\n")
}

// ---- New-since-last-scan detection (for proactive notifications) ---------
//
// `lastSeenMap` is `{"<repoPath>": ["<findingId>", ...]}`, the id set from
// each repo's previous successful scan. Only repos included in `repos` get
// their entry touched — a single-project rescan naturally leaves every
// other repo's baseline alone — and a repo whose scan didn't succeed this
// round (missing-tool, parse-error, ...) is skipped entirely rather than
// having its baseline overwritten: zero findings because the scan *failed*
// must never be read as "everything got fixed" next time it succeeds.
// A repo with no prior baseline at all (first scan ever, freshly added to
// config) reports no new findings — everything found on a first scan is
// "new" only in a trivial sense that would spam a notification on every
// fresh install.
function computeNewFindings(repos, lastSeenMap) {
  var newFindings = []
  var nextLastSeen = {}
  for (var k in lastSeenMap) nextLastSeen[k] = lastSeenMap[k]

  for (var i = 0; i < repos.length; i++) {
    var repo = repos[i]
    if (repo.status !== "ok") continue
    var findings = repo.findings || []
    var currentIds = []
    for (var f = 0; f < findings.length; f++) {
      if (findings[f].id !== "") currentIds.push(findings[f].id)
    }

    var previousIds = lastSeenMap ? lastSeenMap[repo.path] : undefined
    if (Array.isArray(previousIds)) {
      var previousSet = {}
      for (var p = 0; p < previousIds.length; p++) previousSet[previousIds[p]] = true
      for (var g = 0; g < findings.length; g++) {
        if (findings[g].id !== "" && !previousSet[findings[g].id])
          newFindings.push({ repoLabel: repo.label, finding: findings[g] })
      }
    }

    nextLastSeen[repo.path] = currentIds
  }

  return { newFindings: newFindings, nextLastSeen: nextLastSeen }
}

// Drops any lastSeenMap entry whose repo path isn't in currentPaths.
// computeNewFindings above only ever *adds to or refreshes* entries — a
// repo removed from config/discovery keeps its baseline forever
// otherwise, so state.json grows without bound over a long-lived install
// with many come-and-go projects. Safe to call after any scan (full or
// single-repo): currentPaths should always be the full current
// effectiveProjects list, not just whatever was in this particular scan
// batch, so a single-repo rescan doesn't wrongly drop every other repo's
// baseline — only a repo no longer configured/discovered at all loses
// its entry.
function pruneLastSeen(lastSeenMap, currentPaths) {
  var keep = {}
  for (var i = 0; i < currentPaths.length; i++) keep[currentPaths[i]] = true
  var next = {}
  for (var k in lastSeenMap) {
    if (keep[k]) next[k] = lastSeenMap[k]
  }
  return next
}

// Notification text for a batch of new findings — names up to 2 by package,
// "+N more" beyond that, so the toast stays short regardless of how many
// showed up at once.
// plainText() on package/id: this string goes into a desktop notification
// sent over the standard freedesktop Notify D-Bus call, which many
// notification daemons render as markup per the spec's optional
// "body-markup" capability (<b>, <a href="...">, even <img src="...">) —
// a malicious package name could otherwise inject that markup, up to and
// including making the daemon fetch an attacker's image URL. Same
// underlying risk class as unescaped registry/project data reaching a
// QML Text element, just via the notification channel instead of the
// in-panel one.
function newFindingsSummary(newFindings) {
  if (!newFindings || newFindings.length === 0) return ""
  var word = newFindings.length === 1 ? "new finding" : "new findings"
  var names = []
  for (var i = 0; i < Math.min(2, newFindings.length); i++) {
    var f = newFindings[i].finding
    var pkg = plainText(f.package)
    var id = plainText(f.id)
    names.push(pkg + (id ? " (" + id + ")" : ""))
  }
  var extra = newFindings.length > 2 ? " +" + (newFindings.length - 2) + " more" : ""
  return newFindings.length + " " + word + ": " + names.join(", ") + extra
}

// ---- Project auto-discovery ------------------------------------------------

// One `find` per configured root, pruning dependency/build-output
// directories so discovery doesn't spend time descending into an already-
// discovered project's own node_modules/target/vendor/etc. (which can
// themselves contain thousands of nested manifests belonging to
// dependencies, not the user's own projects). Matches the same manifest
// set buildAuditScript detects. Root paths must be absolute — unlike the
// shell script buildAuditScript generates, this one never expands `~`
// (every path here is single-quoted before reaching bash, same as
// `projects[].path`, specifically so shell metacharacters in a configured
// root can't be interpreted — quoting and `~`-expansion are mutually
// exclusive, so this makes the same tradeoff `projects[].path` already
// makes).
//
// -maxdepth 5: verified against a real clone that a shallower limit (3)
// misses in practice — a .NET repo laid out as the common
// `RepoRoot/src/ProjectName/ProjectName.csproj` sits 4 levels below a
// discoverRoot that's the *parent* of RepoRoot (e.g. ~/Development), one
// past where 3 would still look. That specific repo happened to also carry
// a root .sln (depth 2) so it wasn't actually missed, but a same-shaped
// repo with no root .sln/.csproj — only the nested project files — would
// have been silently skipped.
function buildDiscoveryScript(roots) {
  var parts = []
  for (var i = 0; i < roots.length; i++) {
    var root = String(roots[i] || "")
    if (root === "") continue
    var qRoot = shellQuote(findSafePath(root))
    parts.push(
      "find " + qRoot + " -maxdepth 5 " +
      "\\( -name node_modules -o -name .git -o -name target -o -name vendor " +
      "-o -name .venv -o -name venv -o -name bin -o -name obj -o -name build \\) -prune -o " +
      "\\( -name Cargo.toml -o -name package.json -o -name requirements.txt " +
      "-o -name pyproject.toml -o -name go.mod -o -name Gemfile.lock " +
      "-o -name '*.csproj' -o -name '*.sln' -o -name '*.fsproj' " +
      "-o -name package-lock.json -o -name yarn.lock -o -name pnpm-lock.yaml " +
      "-o -name npm-shrinkwrap.json -o -name Cargo.lock \\) -print 2>/dev/null"
    )
  }
  return parts.join("; ")
}

// Turns buildDiscoveryScript's output (one manifest/lockfile path per line)
// into {label, path} project entries — one per containing directory, deduped
// (a repo can trip more than one manifest pattern, e.g. a workspace with
// both a root package.json and a nested Cargo.toml would otherwise still
// only collapse duplicates of the *same* directory, not merge distinct
// sub-projects, which is the intended behavior for a monorepo-style tree).
//
// Two deliberate exceptions, both "umbrella manifest already covers this"
// cases found via real repos:
//
// 1. A *.csproj/*.fsproj nested under a directory that has its own .sln is
//    dropped, not kept as its own project (root MockServer.API.sln, plus a
//    .csproj under src/MockServer.API/, src/MockServer.Data/, etc.) —
//    buildAuditScript's .NET branch runs `dotnet list package --vulnerable
//    --include-transitive` at the matched directory, and at the .sln's own
//    directory that already resolves every project the solution
//    references. Only .sln gets this treatment — a bare .csproj nested
//    under another bare .csproj is left alone, since (unlike .sln) there's
//    no general way to tell from discovery alone whether one references
//    the other.
//
// 2. A "coverable" manifest (package.json or Cargo.toml) with no lockfile
//    of its own is dropped when an ancestor directory has both the SAME
//    manifest filename *and* a matching lockfile — e.g. package.json is
//    covered by an ancestor package.json+(package-lock.json/yarn.lock/
//    pnpm-lock.yaml/npm-shrinkwrap.json), Cargo.toml by an ancestor
//    Cargo.toml+Cargo.lock. Matching by manifest type keeps the two
//    ecosystems from cross-covering each other.
//
//    package.json: found via a real yarn workspace (Backstage-style: root
//    package.json+yarn.lock declaring `workspaces: ["packages/*",
//    "plugins/*"]`). Workspace members like packages/app and
//    packages/backend have no lockfile of their own (they resolve through
//    the root's), so without this they fell back to buildAuditScript's
//    plain `npm audit` branch — which runs regardless of whether a
//    package-lock.json actually exists, producing no real results — while
//    the repo also fragmented into one bogus "project" per member. The
//    same rule also correctly drops non-workspace scaffold/template
//    package.json files nested anywhere under a real project root (found
//    in the same repo: examples/template/content/package.json, a Backstage
//    software-template placeholder with `"name": "${{ values.name }}"` and
//    no real dependencies) — not because it's a workspace member, but
//    because it likewise has no lockfile of its own and isn't
//    independently auditable either way.
//
//    Cargo.toml: found by testing a real cargo workspace directly —
//    `cargo audit` run inside a workspace member directory (which has no
//    Cargo.lock of its own; only the workspace root does) fails outright
//    ("error: not found: Couldn't load Cargo.lock") rather than falling
//    back to anything, unlike a genuinely standalone crate with no
//    committed lockfile at all (verified separately: cargo auto-generates
//    one on the fly and audits fine) — it's specifically being *inside a
//    workspace* that breaks it. A manifest dir that DOES have its own
//    matching lockfile is never dropped by this rule — that's a genuinely
//    independent, already-resolved project.
var COVERABLE_MANIFEST_LOCKFILES = {
  "package.json": { "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "npm-shrinkwrap.json": true },
  "Cargo.toml": { "Cargo.lock": true }
}
function parseDiscoveredProjects(rawText) {
  var lines = String(rawText || "").split("\n")
  var seen = {}
  var dirs = []
  var slnDirs = []
  var lockfileDirs = {}
  var manifestDirsByType = {}
  var allLockfileNames = {}
  for (var manifestName in COVERABLE_MANIFEST_LOCKFILES) {
    manifestDirsByType[manifestName] = {}
    for (var lockName in COVERABLE_MANIFEST_LOCKFILES[manifestName]) allLockfileNames[lockName] = true
  }
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (line === "") continue
    var slash = line.lastIndexOf("/")
    var dir = slash === -1 ? line : line.substring(0, slash)
    var filename = slash === -1 ? line : line.substring(slash + 1)
    if (dir === "") continue
    if (allLockfileNames[filename]) { lockfileDirs[dir] = true; continue }
    if (manifestDirsByType[filename]) manifestDirsByType[filename][dir] = true
    if (/\.sln$/.test(filename) && slnDirs.indexOf(dir) === -1) slnDirs.push(dir)
    if (seen[dir]) continue
    seen[dir] = true
    dirs.push(dir)
  }
  function isNestedUnder(dir, ancestor) {
    return dir !== ancestor && dir.indexOf(ancestor + "/") === 0
  }
  var out = []
  for (var j = 0; j < dirs.length; j++) {
    var d = dirs[j]
    var coveredBySln = false
    for (var k = 0; k < slnDirs.length; k++) {
      if (isNestedUnder(d, slnDirs[k])) { coveredBySln = true; break }
    }
    if (coveredBySln) continue
    var coveredByLockfileAncestor = false
    for (var manifestName in COVERABLE_MANIFEST_LOCKFILES) {
      if (!manifestDirsByType[manifestName][d] || lockfileDirs[d]) continue
      for (var m = 0; m < dirs.length; m++) {
        var a = dirs[m]
        if (a !== d && manifestDirsByType[manifestName][a] && lockfileDirs[a] && isNestedUnder(d, a)) {
          coveredByLockfileAncestor = true
          break
        }
      }
      if (coveredByLockfileAncestor) break
    }
    if (coveredByLockfileAncestor) continue
    var labelSlash = d.lastIndexOf("/")
    var label = labelSlash === -1 ? d : d.substring(labelSlash + 1)
    out.push({ label: label || d, path: d })
  }
  return out
}

// Combines explicit `projects` config with auto-discovered ones, explicit
// entries winning on a path collision (an explicit label override for a
// path discovery also would have found takes precedence over discovery's
// directory-name guess).
function mergeProjects(explicitProjects, discoveredProjects) {
  var seen = {}
  var out = []
  for (var i = 0; i < explicitProjects.length; i++) {
    var p = explicitProjects[i]
    if (p.path) seen[p.path] = true
    out.push(p)
  }
  for (var j = 0; j < discoveredProjects.length; j++) {
    var d = discoveredProjects[j]
    if (!seen[d.path]) {
      seen[d.path] = true
      out.push(d)
    }
  }
  return out
}

// Bar-pill text: icon is added by the widget, this is just the count (or
// nothing when clean, so a healthy state doesn't shout a "0").
function badgeLabel(total) {
  return total > 0 ? String(total) : ""
}

// Universal red/amber meaning — deliberately not drawn from the active
// theme's accent, since severity color-coding needs to mean the same thing
// across every theme. `null` defers to the bar's normal foreground.
// "unknown" gets its own neutral gray, distinct from "low"'s yellow — it
// means the advisory source never assigned a severity at all (verified
// against a real cargo-audit run: RustSec advisories frequently carry no
// CVSS vector — RUSTSEC-2026-0204/0098/0099 in a real repo all had
// `cvss: null`), not "this was rated low risk". Sharing low's color would
// visually claim a rating that was never actually made.
function severityColor(severity) {
  if (severity === "critical" || severity === "high") return "#e05252"
  if (severity === "moderate") return "#e0a83f"
  if (severity === "low") return "#c9b458"
  if (severity === "unknown") return "#8a8f98"
  return null
}

// Human-facing label for a severity — every value passes through
// unchanged except "unknown", which reads as "no CVSS data" instead. Kept
// separate from the raw severity string (used as-is for SEVERITY_RANK,
// countBySeverity's object keys, filtering, etc.) so nothing outside
// display code needs to know about the friendlier wording.
function severityLabel(severity) {
  return severity === "unknown" ? "no CVSS data" : severity
}

// Right-click summary sent as a desktop notification, so the count is
// glanceable without opening the panel at all.
function notificationSummary(total, worstSeverity) {
  if (total === 0) return "No known dependency findings across your configured projects."
  var word = total === 1 ? "finding" : "findings"
  var worst = (worstSeverity !== "none" && worstSeverity !== "unknown") ? " (worst: " + worstSeverity + ")" : ""
  return total + " dependency " + word + worst + " — click the bar badge for details."
}

if (typeof module !== "undefined") {
  module.exports = {
    REPO_MARKER: REPO_MARKER,
    shellQuote: shellQuote,
    findSafePath: findSafePath,
    clipboardSafeText: clipboardSafeText,
    pickCveAlias: pickCveAlias,
    plainText: plainText,
    defaultProjects: defaultProjects,
    SUPPORTED_ECOSYSTEMS: SUPPORTED_ECOSYSTEMS,
    supportedEcosystemsText: supportedEcosystemsText,
    buildAuditScript: buildAuditScript,
    parseAuditOutput: parseAuditOutput,
    buildPendingRepos: buildPendingRepos,
    MAX_COLLECTED_BYTES: MAX_COLLECTED_BYTES,
    buildOversizedOutputRepos: buildOversizedOutputRepos,
    parseNpmAudit: parseNpmAudit,
    parsePnpmAudit: parsePnpmAudit,
    parseYarnAudit: parseYarnAudit,
    parseCargoAudit: parseCargoAudit,
    cvssBaseSeverity: cvssBaseSeverity,
    parsePipAudit: parsePipAudit,
    parseJsonStream: parseJsonStream,
    parseGoAudit: parseGoAudit,
    parseRubyAudit: parseRubyAudit,
    parseDotnetAudit: parseDotnetAudit,
    normalizeSeverity: normalizeSeverity,
    aggregate: aggregate,
    countBySeverity: countBySeverity,
    filterFindings: filterFindings,
    paginateFindings: paginateFindings,
    SEVERITY_FILTERS: SEVERITY_FILTERS,
    parseProjectsText: parseProjectsText,
    projectsToText: projectsToText,
    parseRootsText: parseRootsText,
    rootsToText: rootsToText,
    computeNewFindings: computeNewFindings,
    pruneLastSeen: pruneLastSeen,
    newFindingsSummary: newFindingsSummary,
    buildDiscoveryScript: buildDiscoveryScript,
    parseDiscoveredProjects: parseDiscoveredProjects,
    mergeProjects: mergeProjects,
    badgeLabel: badgeLabel,
    severityColor: severityColor,
    severityLabel: severityLabel,
    notificationSummary: notificationSummary
  }
}
