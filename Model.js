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

// Sanitized because Text elements with AutoText rich-text-parse a crafted
// setting (e.g. a label containing "<img src=...>"). Strips the characters
// that could smuggle markup into the long-lived shell process.
function plainText(value) {
  return String(value === null || value === undefined ? "" : value).replace(/[<>&]/g, "")
}

// No example paths: unlike a timezone list, project paths are inherently
// personal, so there is no sane default. An empty config renders as
// "no projects configured" in the panel rather than auditing nothing
// silently.
function defaultProjects() {
  return []
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
var PATH_PREFIX = "export PATH=\"$HOME/.cargo/bin:$HOME/go/bin:$HOME/.local/bin:"
  + "$HOME/.local/share/mise/shims:$HOME/.dotnet:$PATH\"; "

function buildAuditScript(projects) {
  var parts = []
  for (var i = 0; i < projects.length; i++) {
    var path = String(projects[i].path || "")
    if (path === "") continue
    var qPath = shellQuote(path)

    parts.push(
      "if [ -f " + qPath + "/Cargo.toml ]; then" +
      " if command -v cargo-audit >/dev/null 2>&1; then" +
      "  " + markerEcho(i, "cargo") + ";" +
      "  (cd " + qPath + " && cargo audit --json 2>/dev/null);" +
      " else " + markerEcho(i, "missing:cargo-audit") + "; fi;" +
      "elif [ -f " + qPath + "/package.json ]; then" +
      " if command -v npm >/dev/null 2>&1; then" +
      "  " + markerEcho(i, "npm") + ";" +
      "  (cd " + qPath + " && npm audit --json 2>/dev/null);" +
      " else " + markerEcho(i, "missing:npm") + "; fi;" +
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
  var chunks = text.split(REPO_MARKER)
  var byIndex = {}
  for (var i = 1; i < chunks.length; i++) {
    var chunk = chunks[i]
    var nl = chunk.indexOf("\n")
    var head = nl === -1 ? chunk : chunk.substring(0, nl)
    var body = nl === -1 ? "" : chunk.substring(nl + 1)
    var sep = head.indexOf("|")
    var index = parseInt(sep === -1 ? head : head.substring(0, sep), 10)
    var manager = sep === -1 ? "unknown" : head.substring(sep + 1)
    if (isNaN(index) || !projects[index]) continue
    byIndex[index] = parseRepoBlock(projects[index].label || projects[index].path, projects[index].path, manager, body)
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

function parseRepoBlock(label, path, manager, body) {
  var base = { label: plainText(label), path: path, manager: manager }

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

  // govulncheck's `-json` output is a stream of concatenated top-level JSON
  // values, not one document — JSON.parse would throw on it, so "go" is
  // parsed straight from the raw text via parseJsonStream rather than
  // through the single JSON.parse the other managers use.
  var findings
  if (manager === "go") {
    findings = parseGoAudit(body)
  } else {
    var json = null
    try {
      json = JSON.parse(body)
    } catch (e) {
      return Object.assign(base, { status: "parse-error", findings: [], worstSeverity: "none" })
    }
    if (manager === "npm") findings = parseNpmAudit(json)
    else if (manager === "cargo") findings = parseCargoAudit(json)
    else if (manager === "pip") findings = parsePipAudit(json)
    else if (manager === "ruby") findings = parseRubyAudit(json)
    else if (manager === "dotnet") findings = parseDotnetAudit(json)
    else findings = []
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
      depth--
      if (depth === 0 && start !== -1) {
        try { objects.push(JSON.parse(str.substring(start, i + 1))) } catch (e) { /* skip malformed chunk */ }
        start = -1
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
    total += repos[i].findings.length
    if (SEVERITY_RANK[repos[i].worstSeverity] > SEVERITY_RANK[worst]) worst = repos[i].worstSeverity
  }
  return { total: total, worstSeverity: worst }
}

// Bar-pill text: icon is added by the widget, this is just the count (or
// nothing when clean, so a healthy state doesn't shout a "0").
function badgeLabel(total) {
  return total > 0 ? String(total) : ""
}

// Universal red/amber meaning — deliberately not drawn from the active
// theme's accent, since severity color-coding needs to mean the same thing
// across every theme. `null` defers to the bar's normal foreground.
function severityColor(severity) {
  if (severity === "critical" || severity === "high") return "#e05252"
  if (severity === "moderate") return "#e0a83f"
  if (severity === "low" || severity === "unknown") return "#c9b458"
  return null
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
    pickCveAlias: pickCveAlias,
    plainText: plainText,
    defaultProjects: defaultProjects,
    buildAuditScript: buildAuditScript,
    parseAuditOutput: parseAuditOutput,
    parseNpmAudit: parseNpmAudit,
    parseCargoAudit: parseCargoAudit,
    cvssBaseSeverity: cvssBaseSeverity,
    parsePipAudit: parsePipAudit,
    parseJsonStream: parseJsonStream,
    parseGoAudit: parseGoAudit,
    parseRubyAudit: parseRubyAudit,
    parseDotnetAudit: parseDotnetAudit,
    normalizeSeverity: normalizeSeverity,
    aggregate: aggregate,
    badgeLabel: badgeLabel,
    severityColor: severityColor,
    notificationSummary: notificationSummary
  }
}
