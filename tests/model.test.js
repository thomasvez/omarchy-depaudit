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

test("buildAuditScript on an empty project list is just the PATH prefix", () => {
  const script = Model.buildAuditScript([])
  assert.match(script, /^export PATH=.*\$PATH"; $/)
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

test("parseAuditOutput: missing-tool and unknown-manifest statuses carry no findings", () => {
  const projects = [{ label: "a", path: "/x/a" }, { label: "b", path: "/x/b" }]
  const raw = Model.REPO_MARKER + "0|missing:cargo-audit\n"
    + Model.REPO_MARKER + "1|unknown\n"
  const repos = Model.parseAuditOutput(raw, projects)
  assert.equal(repos[0].status, "missing-tool")
  assert.equal(repos[0].tool, "cargo-audit")
  assert.equal(repos[0].findings.length, 0)
  assert.equal(repos[1].status, "unrecognized")
  assert.equal(repos[1].findings.length, 0)
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

// ---- Integration: buildAuditScript output actually runs in bash ----------
//
// Doesn't require any of the six audit tools to be installed — the paths
// deliberately match none of the manifest files buildAuditScript checks
// for, so every project takes the "unknown" branch. What this locks in is
// the plumbing itself: PATH_PREFIX doesn't break the script, quoting holds
// under bash, and REPO_MARKER round-trips correctly end to end through a
// real shell.

test("a generated script actually runs correctly under bash", () => {
  const projects = [
    { label: "has space", path: "/tmp/depaudit-test-dir with space" },
    { label: "has quote", path: "/tmp/depaudit-test-dir-it's-here" }
  ]
  const script = Model.buildAuditScript(projects)
  const stdout = execFileSync("bash", ["-c", script], { encoding: "utf8" })
  const repos = Model.parseAuditOutput(stdout, projects)
  assert.equal(repos.length, 2)
  assert.equal(repos[0].status, "unrecognized")
  assert.equal(repos[1].status, "unrecognized")
})

test("defaultProjects is an empty array", () => {
  assert.deepEqual(Model.defaultProjects(), [])
})
