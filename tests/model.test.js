// Regression tests for Model.js's pure logic. No QML/Quickshell here — only
// what already runs standalone in Node (see Model.js's own module.exports
// guard). Run with `node --test`.
//
// Fixtures under tests/fixtures/ are REAL captured output from the actual
// tools (npm 11, cargo-audit 0.22.2, pip-audit 2.10.1, govulncheck 1.7.0,
// bundler-audit 0.9.3, dotnet 10 SDK), not hand-written approximations —
// every parser bug found during development (npm's multi-advisory `via`
// array, pip-audit's `{dependencies:[...]}` wrapper, govulncheck's
// concatenated-JSON-stream output) was caught by testing against real tool
// output, not by guessing at a shape. govulncheck.json is trimmed to just
// the 4 matched findings and their osv records (the full run also dumps
// ~170 non-matching advisories it merely consulted) — still real data, just
// filtered, to keep the fixture a reasonable size.

const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const os = require("node:os")
const path = require("node:path")
const { execFileSync } = require("node:child_process")

const Model = require("../Model.js")

function fixture(name) {
  return fs.readFileSync(path.join(__dirname, "fixtures", name), "utf8")
}

function fixtureJson(name) {
  return JSON.parse(fixture(name))
}

// ---- shellQuote / plainText -------------------------------------------

test("shellQuote wraps in single quotes and escapes embedded ones", () => {
  assert.equal(Model.shellQuote("hello"), "'hello'")
  assert.equal(Model.shellQuote("it's a test"), "'it'\\''s a test'")
  assert.equal(Model.shellQuote(""), "''")
  assert.equal(Model.shellQuote(null), "''")
})

test("plainText strips markup-smuggling characters only", () => {
  assert.equal(Model.plainText('<img src=x onerror=alert(1)>'), "img src=x onerror=alert(1)")
  assert.equal(Model.plainText("normal label"), "normal label")
  assert.equal(Model.plainText(null), "")
})

// ---- pickCveAlias --------------------------------------------------------

test("pickCveAlias prefers a real CVE id and ignores GHSA/others", () => {
  assert.equal(Model.pickCveAlias(["GHSA-xxxx-yyyy-zzzz", "CVE-2020-8161"]), "CVE-2020-8161")
  assert.equal(Model.pickCveAlias(["CVE-2020-8161", "GHSA-xxxx-yyyy-zzzz"]), "CVE-2020-8161")
})

test("pickCveAlias returns null when no CVE is present", () => {
  assert.equal(Model.pickCveAlias(["GHSA-xxxx-yyyy-zzzz"]), null)
  assert.equal(Model.pickCveAlias([]), null)
  assert.equal(Model.pickCveAlias(undefined), null)
  assert.equal(Model.pickCveAlias(null), null)
})

// ---- normalizeSeverity ---------------------------------------------------

test("normalizeSeverity lowercases, maps medium->moderate, else unknown", () => {
  assert.equal(Model.normalizeSeverity("Critical"), "critical")
  assert.equal(Model.normalizeSeverity("HIGH"), "high")
  assert.equal(Model.normalizeSeverity("Medium"), "moderate")
  assert.equal(Model.normalizeSeverity("moderate"), "moderate")
  assert.equal(Model.normalizeSeverity("low"), "low")
  assert.equal(Model.normalizeSeverity("something-else"), "unknown")
  assert.equal(Model.normalizeSeverity(undefined), "unknown")
})

// ---- cvssBaseSeverity ------------------------------------------------

test("cvssBaseSeverity scores RUSTSEC-2020-0071's real vector to 6.2/moderate", () => {
  // Verified during development against the published NVD score for
  // CVE-2020-26235 (6.2 MEDIUM) — this pins that match permanently.
  const severity = Model.cvssBaseSeverity("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
  assert.equal(severity, "moderate")
})

test("cvssBaseSeverity covers the full critical/high/moderate/low range", () => {
  // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 critical (textbook worst case)
  assert.equal(Model.cvssBaseSeverity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "critical")
  // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N -> 7.5 high
  assert.equal(Model.cvssBaseSeverity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), "high")
  // AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N -> low end of the scale
  assert.equal(Model.cvssBaseSeverity("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"), "low")
})

test("cvssBaseSeverity returns unknown for a missing or malformed vector", () => {
  assert.equal(Model.cvssBaseSeverity(""), "unknown")
  assert.equal(Model.cvssBaseSeverity(null), "unknown")
  assert.equal(Model.cvssBaseSeverity("not-a-vector"), "unknown")
  assert.equal(Model.cvssBaseSeverity("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), "unknown")
})

// ---- severityColor / badgeLabel / notificationSummary --------------------

test("severityColor returns a color for known severities, null for none", () => {
  assert.ok(Model.severityColor("critical"))
  assert.ok(Model.severityColor("high"))
  assert.ok(Model.severityColor("moderate"))
  assert.ok(Model.severityColor("low"))
  assert.ok(Model.severityColor("unknown"))
  assert.equal(Model.severityColor("none"), null)
})

test("severityColor gives 'unknown' its own color, distinct from 'low'", () => {
  assert.notEqual(Model.severityColor("unknown"), Model.severityColor("low"))
})

test("severityLabel reads 'unknown' as 'no CVSS data', passes everything else through unchanged", () => {
  assert.equal(Model.severityLabel("unknown"), "no CVSS data")
  assert.equal(Model.severityLabel("critical"), "critical")
  assert.equal(Model.severityLabel("high"), "high")
  assert.equal(Model.severityLabel("moderate"), "moderate")
  assert.equal(Model.severityLabel("low"), "low")
})

test("badgeLabel is empty for zero findings, the count otherwise", () => {
  assert.equal(Model.badgeLabel(0), "")
  assert.equal(Model.badgeLabel(5), "5")
})

test("notificationSummary mentions the worst severity only when known", () => {
  assert.match(Model.notificationSummary(0, "none"), /no known/i)
  assert.match(Model.notificationSummary(1, "critical"), /1 dependency finding \(worst: critical\)/)
  assert.match(Model.notificationSummary(3, "unknown"), /3 dependency findings/)
  assert.doesNotMatch(Model.notificationSummary(3, "unknown"), /worst:/)
})

// ---- countBySeverity / aggregate ------------------------------------------

test("countBySeverity tallies each bucket and ignores unrecognized values", () => {
  const counts = Model.countBySeverity([
    { severity: "critical" }, { severity: "critical" }, { severity: "high" },
    { severity: "unknown" }, { severity: "unknown" }, { severity: "unknown" }
  ])
  assert.deepEqual(counts, { critical: 2, high: 1, moderate: 0, low: 0, unknown: 3 })
})

test("aggregate sums findings and tracks the single worst severity", () => {
  const summary = Model.aggregate([
    { findings: [{}], worstSeverity: "high" },
    { findings: [{}, {}], worstSeverity: "critical" },
    { findings: [], worstSeverity: "none" }
  ])
  assert.deepEqual(summary, { total: 3, worstSeverity: "critical" })
})

// ---- buildAuditScript ------------------------------------------------

test("buildAuditScript prepends the PATH fix and safely quotes special paths", () => {
  const script = Model.buildAuditScript([{ label: "weird", path: "/tmp/a b's \"project\"" }])
  assert.match(script, /^export PATH="\$HOME\/\.cargo\/bin/)
  // The quoted path must appear as a single-quoted bash literal with the
  // embedded single quote escaped via the close-escape-reopen idiom, not
  // interpolated raw (which would break the script or, worse, let shell
  // metacharacters in a project label/path execute).
  assert.ok(script.includes("'/tmp/a b'\\''s \"project\"'"))
})

test("buildAuditScript skips entries with an empty path", () => {
  const script = Model.buildAuditScript([{ label: "no path", path: "" }])
  assert.equal(script, Model.buildAuditScript([]))
})

test("buildAuditScript on an empty project list is just the setup prefix", () => {
  const script = Model.buildAuditScript([])
  assert.match(script, /^export PATH=.*\$PATH"; mkdir -p .*omarchy-depaudit; $/)
})

// ---- parseJsonStream -------------------------------------------------

test("parseJsonStream splits concatenated top-level JSON values", () => {
  const stream = '{"a":1}{"b":[1,2,{"c":3}]}{"d":"x\\"y"}'
  const objects = Model.parseJsonStream(stream)
  assert.deepEqual(objects, [{ a: 1 }, { b: [1, 2, { c: 3 }] }, { d: 'x"y' }])
})

test("parseJsonStream tolerates braces inside quoted strings", () => {
  const stream = '{"text":"a { b } c"}{"n":2}'
  const objects = Model.parseJsonStream(stream)
  assert.deepEqual(objects, [{ text: "a { b } c" }, { n: 2 }])
})

// ---- Real fixture parsing -------------------------------------------------

test("parseNpmAudit: one finding per distinct GHSA advisory, not just the first", () => {
  // The real bug this pins: minimist matches TWO separate advisories
  // (moderate + critical) in one `via` array; the original code kept only
  // via[0] and silently dropped the second, undercounting real findings.
  const findings = Model.parseNpmAudit(fixtureJson("npm-audit.json"))
  assert.equal(findings.length, 2)
  const bySeverity = Object.fromEntries(findings.map(f => [f.severity, f]))
  assert.ok(bySeverity.moderate)
  assert.ok(bySeverity.critical)
  assert.equal(bySeverity.moderate.id, "GHSA-vh95-rmgr-6w4m")
  assert.equal(bySeverity.critical.id, "GHSA-xvch-5gv4-984h")
  for (const f of findings) {
    assert.equal(f.package, "minimist")
    assert.equal(f.fixedVersion, "1.2.8")
    assert.equal(f.fixCommand, "npm install minimist@1.2.8")
    assert.match(f.url, /^https:\/\/github\.com\/advisories\/GHSA-/)
  }
})

test("parsePnpmAudit: reads the legacy per-advisory-id schema, real severity", () => {
  const findings = Model.parsePnpmAudit(fixtureJson("pnpm-audit.json"))
  assert.equal(findings.length, 2)
  const bySeverity = Object.fromEntries(findings.map(f => [f.severity, f]))
  assert.equal(bySeverity.moderate.id, "GHSA-vh95-rmgr-6w4m")
  assert.equal(bySeverity.critical.id, "GHSA-xvch-5gv4-984h")
  for (const f of findings) {
    assert.equal(f.package, "minimist")
    assert.equal(f.range, "0.0.8")
    assert.equal(f.fixCommand, "pnpm update minimist")
  }
})

test("parseYarnAudit: reads newline-delimited JSON, prefers the real cves array", () => {
  const findings = Model.parseYarnAudit(fixture("yarn-audit.json"))
  assert.equal(findings.length, 2)
  const bySeverity = Object.fromEntries(findings.map(f => [f.severity, f]))
  // yarn's advisory carries a real `cves` array unlike pnpm's/npm's shape —
  // pickCveAlias should win over the GHSA id here.
  assert.equal(bySeverity.moderate.id, "CVE-2020-7598")
  assert.equal(bySeverity.critical.id, "CVE-2021-44906")
  for (const f of findings) {
    assert.equal(f.package, "minimist")
    assert.equal(f.fixCommand, "yarn upgrade minimist")
  }
})

test("parseYarnAudit ignores non-auditAdvisory lines (auditSummary, etc.)", () => {
  const stream = '{"type":"info","data":"whatever"}\n{"type":"auditSummary","data":{}}\n'
  assert.deepEqual(Model.parseYarnAudit(stream), [])
})

test("parseYarnAudit dedupes the same advisory reached via many dependency paths", () => {
  // Regression test for a real ~3000-finding workspace where the same
  // `tar` advisory repeated once per workspace member that pulled it in —
  // yarn classic emits one auditAdvisory event per dependency *path*, not
  // per distinct vulnerability. Same advisory.id (999), three different
  // resolution paths/ids, one genuinely different advisory (1000) mixed
  // in to confirm it isn't also collapsed.
  function advisoryLine(advisoryId, resolutionId, path, moduleName) {
    return JSON.stringify({
      type: "auditAdvisory",
      data: {
        resolution: { id: resolutionId, path: path },
        advisory: {
          id: advisoryId,
          module_name: moduleName,
          severity: "critical",
          cves: ["CVE-2026-59873"],
          github_advisory_id: "GHSA-xxxx",
          findings: [{ version: "6.2.1", paths: [path] }],
          patched_versions: ">=7.5.19",
          title: "node-tar: Decompression/parse DoS",
          url: "https://github.com/advisories/GHSA-xxxx"
        }
      }
    })
  }
  const stream = [
    advisoryLine(999, 1, "packages/app > tar", "tar"),
    advisoryLine(999, 2, "packages/backend > tar", "tar"),
    advisoryLine(999, 3, "plugins/foo > some-dep > tar", "tar"),
    advisoryLine(1000, 4, "packages/app > brace-expansion", "brace-expansion")
  ].join("\n")
  const findings = Model.parseYarnAudit(stream)
  assert.equal(findings.length, 2)
  assert.deepEqual(findings.map(f => f.package).sort(), ["brace-expansion", "tar"])
})

test("parseCargoAudit: scores CVSS into a real severity and links to RustSec", () => {
  const findings = Model.parseCargoAudit(fixtureJson("cargo-audit.json"))
  assert.equal(findings.length, 1)
  const [f] = findings
  assert.equal(f.package, "time")
  assert.equal(f.severity, "moderate")
  assert.equal(f.id, "CVE-2020-26235")
  assert.equal(f.url, "https://rustsec.org/advisories/RUSTSEC-2020-0071.html")
  assert.equal(f.fixCommand, "cargo update -p time")
})

test("parsePipAudit: reads the real {dependencies:[...]} wrapper, not a bare array", () => {
  const findings = Model.parsePipAudit(fixtureJson("pip-audit.json"))
  assert.equal(findings.length, 14)
  const requestsFinding = findings.find(f => f.id === "CVE-2023-32681")
  assert.ok(requestsFinding)
  assert.equal(requestsFinding.package, "requests")
  assert.equal(requestsFinding.severity, "unknown")
  assert.equal(requestsFinding.url, "https://osv.dev/vulnerability/PYSEC-2023-74")
  assert.equal(requestsFinding.fixCommand, "pip install requests==2.31.0")
})

test("parseGoAudit: pulls findings out of the concatenated stream via osv cross-reference", () => {
  const findings = Model.parseGoAudit(fixture("govulncheck.json"))
  assert.equal(findings.length, 4)
  const cve2021 = findings.find(f => f.id === "CVE-2021-38561")
  assert.ok(cve2021)
  assert.equal(cve2021.package, "golang.org/x/text")
  assert.equal(cve2021.fixedVersion, "v0.3.7")
  assert.equal(cve2021.fixCommand, "go get golang.org/x/text@v0.3.7")
  assert.equal(cve2021.url, "https://pkg.go.dev/vuln/GO-2021-0113")
})

test("parseRubyAudit: only unpatched_gem entries, real severity, RubySec link", () => {
  const findings = Model.parseRubyAudit(fixtureJson("bundler-audit.json"))
  assert.equal(findings.length, 34)
  for (const f of findings) assert.equal(f.package, "rack")
  const cve2020 = findings.find(f => f.id === "CVE-2020-8161")
  assert.ok(cve2020)
  assert.equal(cve2020.severity, "high")
  assert.equal(cve2020.url, "https://rubysec.com/advisories/CVE-2020-8161/")
  assert.equal(cve2020.fixCommand, "bundle update rack")
})

test("parseDotnetAudit: reads topLevelPackages, GHSA-slug id, generic re-add fix", () => {
  const findings = Model.parseDotnetAudit(fixtureJson("dotnet-list-package.json"))
  assert.equal(findings.length, 1)
  const [f] = findings
  assert.equal(f.package, "System.Text.Encodings.Web")
  assert.equal(f.severity, "critical")
  assert.equal(f.id, "GHSA-ghhp-997w-qr28")
  assert.equal(f.fixedVersion, null)
  assert.equal(f.fixCommand, "dotnet add package System.Text.Encodings.Web")
})

test("parseDotnetAudit dedupes the same vulnerable package shared across multiple projects in one solution", () => {
  // Regression test for the same duplication shape as parseYarnAudit's
  // fix: `dotnet list package --vulnerable` at a .sln reports results per
  // PROJECT, so a package several projects all reference transitively
  // (common in a real multi-project solution) repeated once per project.
  const json = {
    projects: [
      { path: "A.csproj", frameworks: [{ framework: "net8.0", topLevelPackages: [], transitivePackages: [
        { id: "System.Text.Json", resolvedVersion: "8.0.0", vulnerabilities: [
          { severity: "High", advisoryurl: "https://github.com/advisories/GHSA-hh2w-p6rv-4g7w" }
        ] }
      ] }] },
      { path: "B.csproj", frameworks: [{ framework: "net8.0", topLevelPackages: [], transitivePackages: [
        { id: "System.Text.Json", resolvedVersion: "8.0.0", vulnerabilities: [
          { severity: "High", advisoryurl: "https://github.com/advisories/GHSA-hh2w-p6rv-4g7w" }
        ] }
      ] }] },
      { path: "C.csproj", frameworks: [{ framework: "net8.0", topLevelPackages: [
        { id: "SomeOtherPkg", resolvedVersion: "1.0.0", vulnerabilities: [
          { severity: "Moderate", advisoryurl: "https://github.com/advisories/GHSA-other" }
        ] }
      ], transitivePackages: [] }] }
    ]
  }
  const findings = Model.parseDotnetAudit(json)
  assert.equal(findings.length, 2)
  assert.deepEqual(findings.map(f => f.package).sort(), ["SomeOtherPkg", "System.Text.Json"])
})

// ---- parseAuditOutput end-to-end (marker splitting, index-keyed matching) --

test("parseAuditOutput routes each marked chunk to the right parser by manager tag", () => {
  const projects = [
    { label: "npm proj", path: "/x/npm" },
    { label: "cargo proj", path: "/x/cargo" }
  ]
  const raw = Model.REPO_MARKER + "0|npm\n" + fixture("npm-audit.json")
    + "\n" + Model.REPO_MARKER + "1|cargo\n" + fixture("cargo-audit.json")
  const repos = Model.parseAuditOutput(raw, projects)
  assert.equal(repos.length, 2)
  assert.equal(repos[0].manager, "npm")
  assert.equal(repos[0].status, "ok")
  assert.equal(repos[0].findings.length, 2)
  assert.equal(repos[1].manager, "cargo")
  assert.equal(repos[1].findings.length, 1)
})

test("parseAuditOutput: missing-tool, missing-path, and unknown-manifest carry no findings", () => {
  const projects = [{ label: "a", path: "/x/a" }, { label: "b", path: "/x/b" }, { label: "c", path: "/x/c" }]
  const raw = Model.REPO_MARKER + "0|missing:cargo-audit\n"
    + Model.REPO_MARKER + "1|unknown\n"
    + Model.REPO_MARKER + "2|missing-path\n"
  const repos = Model.parseAuditOutput(raw, projects)
  assert.equal(repos[0].status, "missing-tool")
  assert.equal(repos[0].tool, "cargo-audit")
  assert.equal(repos[0].findings.length, 0)
  assert.equal(repos[1].status, "unrecognized")
  assert.equal(repos[1].findings.length, 0)
  assert.equal(repos[2].status, "missing-path")
  assert.equal(repos[2].findings.length, 0)
})

test("parseAuditOutput: malformed JSON body yields parse-error, not a crash", () => {
  const projects = [{ label: "a", path: "/x/a" }]
  const raw = Model.REPO_MARKER + "0|npm\nthis is not json{{{"
  const repos = Model.parseAuditOutput(raw, projects)
  assert.equal(repos[0].status, "parse-error")
  assert.equal(repos[0].findings.length, 0)
})

test("parseAuditOutput: a project with no matching chunk stays pending", () => {
  const projects = [{ label: "never ran", path: "/x/a" }]
  const repos = Model.parseAuditOutput("", projects)
  assert.equal(repos[0].status, "pending")
})

test("buildPendingRepos keeps existing results, placeholders anything not yet scanned", () => {
  const existing = [
    { label: "known", path: "/x/known", manager: "npm", status: "ok", findings: [{ id: "CVE-1" }], worstSeverity: "high" }
  ]
  const projects = [
    { label: "known", path: "/x/known" },
    { label: "brand new", path: "/x/new" }
  ]
  const result = Model.buildPendingRepos(projects, existing)
  assert.equal(result.length, 2)
  assert.equal(result[0], existing[0], "already-scanned repo is reused as-is, not rebuilt")
  assert.equal(result[1].status, "pending")
  assert.equal(result[1].label, "brand new")
  assert.equal(result[1].path, "/x/new")
})

test("buildOversizedOutputRepos reports every project with a distinct, bounded error status", () => {
  const projects = [{ label: "a", path: "/x/a" }, { path: "/x/b" }]
  const repos = Model.buildOversizedOutputRepos(projects)
  assert.equal(repos.length, 2)
  assert.equal(repos[0].label, "a")
  assert.equal(repos[0].status, "output-too-large")
  assert.equal(repos[0].findings.length, 0)
  assert.equal(repos[1].label, "/x/b", "falls back to path when label is missing")
})

// ---- Integration: buildAuditScript output actually runs in bash ----------
//
// Doesn't require any of the six audit tools to be installed — the paths
// deliberately match none of the manifest files buildAuditScript checks
// for, so every project takes the "unknown" branch. What this locks in is
// the plumbing itself: PATH_PREFIX doesn't break the script, quoting holds
// under bash, and REPO_MARKER round-trips correctly end to end through a
// real shell.

test("a generated script correctly reports missing-path for a nonexistent project", () => {
  const projects = [
    { label: "has space", path: "/tmp/depaudit-definitely-nonexistent dir with space" },
    { label: "has quote", path: "/tmp/depaudit-definitely-nonexistent-dir-it's-here" }
  ]
  const script = Model.buildAuditScript(projects)
  const stdout = execFileSync("bash", ["-c", script], { encoding: "utf8" })
  const repos = Model.parseAuditOutput(stdout, projects)
  assert.equal(repos.length, 2)
  assert.equal(repos[0].status, "missing-path")
  assert.equal(repos[1].status, "missing-path")
})

test("a generated script runs correctly under bash for a real path with special characters", () => {
  // Real, unique temp dirs (not just nonexistent path strings) with a
  // space and an embedded single quote in the name — this is what
  // actually exercises buildAuditScript's quoting under bash end to end;
  // the nonexistent-path test above only exercises the `[ ! -d ]` branch.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "depaudit-test-it's-"))
  try {
    const projects = [{ label: "special chars", path: dir }]
    const script = Model.buildAuditScript(projects)
    const stdout = execFileSync("bash", ["-c", script], { encoding: "utf8" })
    const repos = Model.parseAuditOutput(stdout, projects)
    assert.equal(repos.length, 1)
    assert.equal(repos[0].status, "unrecognized")
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test("defaultProjects is an empty array", () => {
  assert.deepEqual(Model.defaultProjects(), [])
})

test("aggregate/countBySeverity total every finding across repos", () => {
  const repos = [{
    path: "/repo/a",
    findings: [
      { id: "CVE-1", severity: "critical" },
      { id: "CVE-2", severity: "low" }
    ],
    worstSeverity: "critical"
  }]
  assert.deepEqual(Model.aggregate(repos), { total: 2, worstSeverity: "critical" })
  assert.deepEqual(Model.countBySeverity(repos[0].findings), { critical: 1, high: 0, moderate: 0, low: 1, unknown: 0 })
})

// ---- Repo detail view: severity filter + pagination -----------------------

test("filterFindings: 'all' returns everything, a severity keeps only matches", () => {
  const findings = [
    { id: "CVE-1", severity: "critical" },
    { id: "CVE-2", severity: "high" },
    { id: "CVE-3", severity: "critical" }
  ]
  assert.equal(Model.filterFindings(findings, "all").length, 3)
  assert.equal(Model.filterFindings(findings, "").length, 3)
  const critical = Model.filterFindings(findings, "critical")
  assert.deepEqual(critical.map(f => f.id), ["CVE-1", "CVE-3"])
})

test("paginateFindings slices by page and reports pageCount/total", () => {
  const findings = Array.from({ length: 45 }, (_, i) => ({ id: "CVE-" + i }))
  const first = Model.paginateFindings(findings, 0, 20)
  assert.equal(first.items.length, 20)
  assert.equal(first.page, 0)
  assert.equal(first.pageCount, 3)
  assert.equal(first.total, 45)

  const last = Model.paginateFindings(findings, 2, 20)
  assert.equal(last.items.length, 5)
  assert.equal(last.page, 2)
})

test("paginateFindings clamps an out-of-range page instead of returning empty", () => {
  const findings = Array.from({ length: 5 }, (_, i) => ({ id: "CVE-" + i }))
  const result = Model.paginateFindings(findings, 99, 20)
  assert.equal(result.page, 0)
  assert.equal(result.items.length, 5)
})

test("paginateFindings never breaks on an empty list", () => {
  const result = Model.paginateFindings([], 0, 20)
  assert.deepEqual(result, { items: [], page: 0, pageCount: 1, total: 0 })
})

// ---- New-since-last-scan detection ----------------------------------------

test("computeNewFindings: no baseline yet means nothing counts as new (first scan)", () => {
  const repos = [{ path: "/repo/a", label: "a", status: "ok", findings: [{ id: "CVE-1", package: "x" }] }]
  const { newFindings, nextLastSeen } = Model.computeNewFindings(repos, {})
  assert.deepEqual(newFindings, [])
  assert.deepEqual(nextLastSeen, { "/repo/a": ["CVE-1"] })
})

test("computeNewFindings: flags an id absent from the previous baseline", () => {
  const repos = [{ path: "/repo/a", label: "a", status: "ok", findings: [
    { id: "CVE-1", package: "x" }, { id: "CVE-2", package: "y" }
  ] }]
  const { newFindings, nextLastSeen } = Model.computeNewFindings(repos, { "/repo/a": ["CVE-1"] })
  assert.equal(newFindings.length, 1)
  assert.equal(newFindings[0].finding.id, "CVE-2")
  assert.deepEqual(nextLastSeen["/repo/a"], ["CVE-1", "CVE-2"])
})

test("computeNewFindings: a failed scan doesn't touch that repo's baseline", () => {
  const repos = [{ path: "/repo/a", label: "a", status: "missing-tool", findings: [] }]
  const { newFindings, nextLastSeen } = Model.computeNewFindings(repos, { "/repo/a": ["CVE-1"] })
  assert.deepEqual(newFindings, [])
  assert.deepEqual(nextLastSeen["/repo/a"], ["CVE-1"], "baseline preserved, not wiped to []")
})

test("computeNewFindings: a single-repo call preserves other repos' baselines untouched", () => {
  const repos = [{ path: "/repo/a", label: "a", status: "ok", findings: [{ id: "CVE-2", package: "x" }] }]
  const existing = { "/repo/a": ["CVE-1"], "/repo/b": ["CVE-9"] }
  const { nextLastSeen } = Model.computeNewFindings(repos, existing)
  assert.deepEqual(nextLastSeen["/repo/b"], ["CVE-9"])
})

test("newFindingsSummary names up to 2 findings and counts the rest", () => {
  assert.equal(Model.newFindingsSummary([]), "")
  const one = [{ finding: { package: "requests", id: "CVE-1" } }]
  assert.equal(Model.newFindingsSummary(one), "1 new finding: requests (CVE-1)")
  const four = [
    { finding: { package: "a", id: "CVE-1" } },
    { finding: { package: "b", id: "CVE-2" } },
    { finding: { package: "c", id: "CVE-3" } },
    { finding: { package: "d", id: "CVE-4" } }
  ]
  assert.equal(Model.newFindingsSummary(four), "4 new findings: a (CVE-1), b (CVE-2) +2 more")
})

// ---- Auto-discovery --------------------------------------------------

test("discovery finds real projects under a root and prunes node_modules", () => {
  // A self-contained fixture tree (not this machine's own demo state, which
  // wouldn't exist on a fresh CI runner): two real projects plus a
  // node_modules directory holding a third-party package's own
  // package.json, which discovery must NOT report as a project.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "depaudit-discovery-"))
  try {
    fs.mkdirSync(path.join(root, "webapp"), { recursive: true })
    fs.writeFileSync(path.join(root, "webapp", "package.json"), "{}")
    fs.mkdirSync(path.join(root, "webapp", "node_modules", "some-dep"), { recursive: true })
    fs.writeFileSync(path.join(root, "webapp", "node_modules", "some-dep", "package.json"), "{}")

    fs.mkdirSync(path.join(root, "cli-tool"), { recursive: true })
    fs.writeFileSync(path.join(root, "cli-tool", "Cargo.toml"), "")

    const script = Model.buildDiscoveryScript([root])
    const stdout = execFileSync("bash", ["-c", script], { encoding: "utf8" })
    const discovered = Model.parseDiscoveredProjects(stdout)
    const labels = discovered.map(d => d.label).sort()
    assert.deepEqual(labels, ["cli-tool", "webapp"])
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test("discovery finds a .csproj nested past the old maxdepth 3 with no shallow .sln to save it", () => {
  // Regression test for a real bug: a .NET repo laid out as the common
  // `RepoRoot/src/ProjectName/ProjectName.csproj` sits 4 levels below a
  // discoverRoot that's the *parent* of RepoRoot — one past where the old
  // `-maxdepth 3` would still look. A real clone was only saved by also
  // having a root .sln at depth 2; this fixture has no root manifest at
  // all, so it would have been silently skipped before the fix to depth 5.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "depaudit-discovery-deep-"))
  try {
    const projectDir = path.join(root, "RepoRoot", "src", "ProjectName")
    fs.mkdirSync(projectDir, { recursive: true })
    fs.writeFileSync(path.join(projectDir, "ProjectName.csproj"), "")

    const script = Model.buildDiscoveryScript([root])
    const stdout = execFileSync("bash", ["-c", script], { encoding: "utf8" })
    const discovered = Model.parseDiscoveredProjects(stdout)
    assert.equal(discovered.length, 1)
    assert.equal(discovered[0].label, "ProjectName")
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test("discovery collapses .csproj files nested under their own .sln into one project", () => {
  // Regression test for a real repo shape found live: MockServer.API.sln
  // at the root, plus a separate .csproj under src/<ProjectName>/ for
  // each project the solution references. Before this fix, deeper
  // discovery (maxdepth 5) reported the root repo *and* every nested
  // .csproj as its own "project" — 5 redundant entries for one repo,
  // since `dotnet list package --vulnerable` at the .sln's directory
  // already covers everything the solution references.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "depaudit-discovery-sln-"))
  try {
    fs.mkdirSync(path.join(root, "mock-server"), { recursive: true })
    fs.writeFileSync(path.join(root, "mock-server", "MockServer.API.sln"), "")
    for (const name of ["MockServer.API", "MockServer.Data", "MockServer.Models"]) {
      const projectDir = path.join(root, "mock-server", "src", name)
      fs.mkdirSync(projectDir, { recursive: true })
      fs.writeFileSync(path.join(projectDir, name + ".csproj"), "")
    }

    const script = Model.buildDiscoveryScript([root])
    const stdout = execFileSync("bash", ["-c", script], { encoding: "utf8" })
    const discovered = Model.parseDiscoveredProjects(stdout)
    assert.equal(discovered.length, 1)
    assert.equal(discovered[0].label, "mock-server")
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test("discovery collapses lockfile-less workspace members into their root, but keeps independently-locked nested repos", () => {
  // Regression test for a real repo shape found live: a yarn workspace
  // (Backstage-style) with a root package.json+yarn.lock declaring
  // `workspaces: ["packages/*", "plugins/*"]`, plus workspace members
  // packages/app and packages/backend with no lockfile of their own, plus
  // an unrelated scaffold package.json (examples/template/content) that's
  // a template placeholder with no real deps and no lockfile either.
  // Before this fix, all 4 discovered as separate "projects" — the 3
  // lockfile-less ones fell back to a broken plain `npm audit` (no
  // package-lock.json to audit against), reported as "many entries, no
  // results". Also verifies a *sibling* project with its own lockfile,
  // nested under the same discoverRoot but not inside the workspace root,
  // is correctly kept — only a lockfile-less package.json covered by an
  // ancestor's own package.json+lockfile gets dropped.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "depaudit-discovery-workspace-"))
  try {
    const repoRoot = path.join(root, "internal-dev-portal")
    fs.mkdirSync(repoRoot, { recursive: true })
    fs.writeFileSync(path.join(repoRoot, "package.json"), JSON.stringify({ workspaces: ["packages/*"] }))
    fs.writeFileSync(path.join(repoRoot, "yarn.lock"), "")

    for (const name of ["app", "backend"]) {
      const memberDir = path.join(repoRoot, "packages", name)
      fs.mkdirSync(memberDir, { recursive: true })
      fs.writeFileSync(path.join(memberDir, "package.json"), "{}")
    }

    const templateDir = path.join(repoRoot, "examples", "template", "content")
    fs.mkdirSync(templateDir, { recursive: true })
    fs.writeFileSync(path.join(templateDir, "package.json"), '{"name":"${{ values.name }}"}')

    const standaloneDir = path.join(root, "other-service")
    fs.mkdirSync(standaloneDir, { recursive: true })
    fs.writeFileSync(path.join(standaloneDir, "package.json"), "{}")
    fs.writeFileSync(path.join(standaloneDir, "package-lock.json"), "{}")

    const script = Model.buildDiscoveryScript([root])
    const stdout = execFileSync("bash", ["-c", script], { encoding: "utf8" })
    const discovered = Model.parseDiscoveredProjects(stdout)
    const labels = discovered.map(d => d.label).sort()
    assert.deepEqual(labels, ["internal-dev-portal", "other-service"])
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test("discovery collapses lockfile-less Cargo workspace members into their root", () => {
  // Regression test verified against a real cargo workspace: `cargo audit`
  // run inside a member crate directory (which has no Cargo.lock of its
  // own — only the workspace root does) fails outright ("Couldn't load
  // Cargo.lock"), unlike a genuinely standalone crate with no committed
  // lockfile (cargo auto-generates one on the fly and audits fine — it's
  // specifically being inside a workspace that breaks it). Same coverage
  // rule as the JS workspace case above, applied to Cargo.toml/Cargo.lock.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "depaudit-discovery-cargo-ws-"))
  try {
    const wsRoot = path.join(root, "my-workspace")
    fs.mkdirSync(wsRoot, { recursive: true })
    fs.writeFileSync(path.join(wsRoot, "Cargo.toml"), '[workspace]\nmembers = ["crate-a", "crate-b"]\n')
    fs.writeFileSync(path.join(wsRoot, "Cargo.lock"), "")

    for (const name of ["crate-a", "crate-b"]) {
      const memberDir = path.join(wsRoot, name)
      fs.mkdirSync(memberDir, { recursive: true })
      fs.writeFileSync(path.join(memberDir, "Cargo.toml"), '[package]\nname = "' + name + '"\n')
    }

    const standaloneDir = path.join(root, "standalone-crate")
    fs.mkdirSync(standaloneDir, { recursive: true })
    fs.writeFileSync(path.join(standaloneDir, "Cargo.toml"), '[package]\nname = "standalone-crate"\n')

    const script = Model.buildDiscoveryScript([root])
    const stdout = execFileSync("bash", ["-c", script], { encoding: "utf8" })
    const discovered = Model.parseDiscoveredProjects(stdout)
    const labels = discovered.map(d => d.label).sort()
    assert.deepEqual(labels, ["my-workspace", "standalone-crate"])
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test("parseDiscoveredProjects dedupes multiple manifest matches in the same directory", () => {
  const raw = "/root/a/package.json\n/root/a/package.json\n/root/b/Cargo.toml\n"
  const discovered = Model.parseDiscoveredProjects(raw)
  assert.equal(discovered.length, 2)
})

test("mergeProjects: explicit config wins over discovery on a path collision", () => {
  const explicit = [{ label: "My Custom Label", path: "/repo/a" }]
  const discovered = [{ label: "a", path: "/repo/a" }, { label: "b", path: "/repo/b" }]
  const merged = Model.mergeProjects(explicit, discovered)
  assert.equal(merged.length, 2)
  assert.equal(merged.find(p => p.path === "/repo/a").label, "My Custom Label")
  assert.ok(merged.find(p => p.path === "/repo/b"))
})

// ---- In-panel settings form text <-> data conversion ----------------------

test("parseProjectsText: label|path, bare path, blank lines, and empty-path lines dropped", () => {
  const text = "work-api | /home/you/work/api\n/home/you/personal/site\n\nweird | \nno-pipe-path"
  assert.deepEqual(Model.parseProjectsText(text), [
    { label: "work-api", path: "/home/you/work/api" },
    { path: "/home/you/personal/site" },
    { path: "no-pipe-path" }
  ])
})

test("projectsToText/parseProjectsText round-trip", () => {
  const projects = [{ label: "a", path: "/x" }, { path: "/y" }]
  assert.deepEqual(Model.parseProjectsText(Model.projectsToText(projects)), projects)
})

test("parseRootsText trims and drops blank lines", () => {
  assert.deepEqual(
    Model.parseRootsText("/home/you/Development\n\n  /home/you/work  \n"),
    ["/home/you/Development", "/home/you/work"]
  )
})

test("rootsToText/parseRootsText round-trip", () => {
  const roots = ["/a", "/b"]
  assert.deepEqual(Model.parseRootsText(Model.rootsToText(roots)), roots)
})

// ---- Supported-ecosystems caption -----------------------------------------

test("supportedEcosystemsText names every ecosystem this plugin actually detects", () => {
  const text = Model.supportedEcosystemsText()
  for (const eco of ["npm", "pnpm", "yarn", "cargo", "pip", "Go", "Ruby", ".NET"]) {
    assert.ok(text.includes(eco), `expected "${text}" to mention ${eco}`)
  }
})
