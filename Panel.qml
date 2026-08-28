import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

// Per-repo dependency-audit breakdown: one section per configured project,
// each listing its findings with severity, current/fixed version, and a
// copyable fix command. The Process/Timer below run continuously in the
// background (this component is loaded eagerly by BarWidget.qml) so the
// bar badge stays current whether or not this popup is open.
Panel {
  id: root
  moduleName: "io.github.thomasvez.depaudit"
  ipcTarget: "io.github.thomasvez.depaudit"
  manageIpc: false

  property var anchorItem: null
  property bool openedFromHotkey: false

  // The bar tracks the widget mounted in its slot — BarWidget.qml — not this
  // nested panel, so everything the bar identifies a panel by must be that
  // widget (popout coordinator, switchPanelFrom).
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  // Deliberately does not force a refresh (unlike a typical weather-style
  // panel): audit commands can hit package registries and take real time,
  // so re-running them on every open would punish repeatedly checking the
  // panel. Data comes from the background Timer below and manual/middle-
  // click refresh instead.
  function open() {
    openedFromHotkey = false
    setCenterHoverRevealSuppressed(false)
    root.controller.show()
  }

  function openFromHotkey() {
    openedFromHotkey = true
    root.controller.show()
    Qt.callLater(function() {
      if (root.opened) setCenterHoverRevealSuppressed(true)
    })
  }

  function close() {
    setCenterHoverRevealSuppressed(false)
    root.controller.hide()
  }

  function toggle() {
    if (root.opened) root.close()
    else root.openFromHotkey()
  }

  function switchPanel(direction) {
    if (root.bar && typeof root.bar.switchPanelFrom === "function")
      return root.bar.switchPanelFrom(root.barIdentity, direction)
    return false
  }

  function setCenterHoverRevealSuppressed(value) {
    if (root.bar && "centerHoverRevealSuppressed" in root.bar)
      root.bar.centerHoverRevealSuppressed = value
  }

  readonly property color fg: bar ? bar.foreground : Color.foreground
  readonly property string fontFam: bar ? bar.fontFamily : Style.font.family

  // ---- Config. `projects` mirrors the timezones plugin's `zones` array
  //      pattern: an array of { path, label } configured per widget instance
  //      in shell.json. No default — project paths are inherently personal.
  readonly property var projects: setting("projects", Model.defaultProjects())

  // `discoverRoots` — absolute directory paths (no `~`, same constraint as
  // `projects[].path` — see buildDiscoveryScript) to walk for projects
  // instead of, or alongside, listing every one by hand. Re-run at the top
  // of every refresh() so a project added later under a configured root
  // shows up without needing a shell.json edit.
  readonly property var discoverRoots: setting("discoverRoots", [])
  property var discoveredProjects: []

  // What actually gets audited: explicit `projects` plus whatever discovery
  // found, explicit entries winning on a path collision (see
  // Model.mergeProjects). Everything downstream — buildAuditScript,
  // refreshOne's bounds check, the "no projects configured" empty state —
  // reads this, not the raw `projects` config.
  readonly property var effectiveProjects: Model.mergeProjects(root.projects, root.discoveredProjects)

  // shell.json edits hot-reload `settings`/`projects`/`discoverRoots`, but
  // nothing else reacts to that on its own — without this, editing either
  // would sit idle until the next timer tick (up to refreshMinutes later)
  // instead of taking effect right away.
  onProjectsChanged: Qt.callLater(root.refresh)
  onDiscoverRootsChanged: Qt.callLater(root.refresh)

  // Recurring re-audit cadence; 0 disables the recurring timer (still runs
  // once on startup/open) for anyone who wants manual/middle-click-only.
  readonly property int refreshMinutes: Math.max(0, parseInt(setting("refreshIntervalMinutes", 60), 10) || 0)

  // Raw scan results — what the UI and the badge read directly.
  property var rawRepos: []
  property bool refreshing: false
  property double lastRefreshedAt: 0

  readonly property var repos: root.rawRepos
  readonly property var summary: Model.aggregate(root.repos)
  readonly property int total: summary.total
  readonly property string worstSeverity: summary.worstSeverity

  // ---- Repo detail view: clicking a repo in the list opens its findings
  //      in a dedicated, much larger view instead of expanding inline —
  //      a repo with a lot of findings made the inline expand genuinely
  //      slow (every finding's Rectangle+Column+MouseAreas built at once,
  //      reflowing the whole popup's height). Paginating (detailPageSize
  //      per page, see below) caps how many finding delegates ever exist
  //      at once regardless of how large a repo's real finding count is.
  property string detailPath: ""
  property string detailSeverity: "all"
  property int detailPage: 0
  readonly property int detailPageSize: 20

  function findRepo(path) {
    for (var i = 0; i < root.repos.length; i++) {
      if (root.repos[i].path === path) return root.repos[i]
    }
    return null
  }

  function findEffectiveIndex(path) {
    for (var i = 0; i < root.effectiveProjects.length; i++) {
      if (root.effectiveProjects[i].path === path) return i
    }
    return -1
  }

  readonly property var detailRepo: root.findRepo(root.detailPath)
  readonly property var detailAllCounts: root.detailRepo ? Model.countBySeverity(root.detailRepo.findings) : ({})
  readonly property var detailFiltered: root.detailRepo ? Model.filterFindings(root.detailRepo.findings, root.detailSeverity) : []
  readonly property var detailPaged: Model.paginateFindings(root.detailFiltered, root.detailPage, root.detailPageSize)

  function openDetail(path) {
    root.detailPath = path
    root.detailSeverity = "all"
    root.detailPage = 0
  }

  function closeDetail() {
    root.detailPath = ""
  }

  function setDetailSeverity(severity) {
    root.detailSeverity = severity
    root.detailPage = 0
  }

  // ---- New-finding baselines: persisted locally (not into shell.json —
  //      this is scan-derived state, not configuration a person would
  //      hand-edit) at ~/.local/state/omarchy-depaudit/state.json. The
  //      directory is created by every generated script's shared setup
  //      prefix (see Model.js's PATH_PREFIX/STATE_DIR) before this
  //      FileView could ever need to write into it.
  readonly property string stateDir: Quickshell.env("HOME") + "/.local/state/omarchy-depaudit"
  property var lastSeenMap: ({})

  function applyState(raw) {
    var parsed = null
    try { parsed = JSON.parse(raw) } catch (e) { parsed = null }
    root.lastSeenMap = (parsed && typeof parsed.lastSeen === "object" && parsed.lastSeen) || {}
  }

  function persistState() {
    stateFile.setText(JSON.stringify({ lastSeen: root.lastSeenMap }, null, 2) + "\n")
  }

  FileView {
    id: stateFile
    path: root.stateDir + "/state.json"
    watchChanges: false
    printErrors: false
    onLoaded: root.applyState(text())
    onLoadFailed: root.applyState("")
  }

  // Compares a batch of just-scanned repos against their previous baseline,
  // notifies once for the whole batch if anything's new, and always
  // updates the baseline (and persists it) regardless — see
  // Model.computeNewFindings for why a failed scan doesn't touch its
  // repo's baseline, and why a repo's first-ever scan never counts as
  // "new" (that would notify on every fresh install).
  function checkNewFindings(scannedRepos) {
    var result = Model.computeNewFindings(scannedRepos, root.lastSeenMap)
    root.lastSeenMap = result.nextLastSeen
    if (result.newFindings.length > 0 && root.bar)
      root.bar.run("omarchy-notification-send " + Util.shellQuote(Model.newFindingsSummary(result.newFindings)))
    root.persistState()
  }

  function anyProcRunning() {
    return auditProc.running || singleProc.running || discoveryProc.running ||
      newProjectsProc.running || newAuditProc.running
  }

  function refresh() {
    if (root.anyProcRunning()) return
    // Shows the project list immediately instead of leaving it blank
    // (first run) or stale (re-run) while discovery/audit — both
    // potentially slow — are still in flight: a project already scanned
    // keeps its real result, anything newly configured shows as
    // "pending" until its own marker shows up in the audit script's
    // output. Only reflects `projects` at this point since discovery
    // hasn't run yet; discoveryProc's own completion below updates it
    // again once discovered projects are known too.
    root.rawRepos = Model.buildPendingRepos(root.effectiveProjects, root.rawRepos)
    if (root.discoverRoots.length === 0) {
      root.discoveredProjects = []
      root.runAudit()
      return
    }
    discoveryProc.command = ["bash", "-c", Model.buildDiscoveryScript(root.discoverRoots)]
    discoveryProc.running = true
  }

  Process {
    id: discoveryProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.discoveredProjects = Model.parseDiscoveredProjects(String(text || ""))
        root.rawRepos = Model.buildPendingRepos(root.effectiveProjects, root.rawRepos)
        root.runAudit()
      }
    }
  }

  function runAudit() {
    if (root.effectiveProjects.length === 0) {
      root.rawRepos = []
      return
    }
    root.refreshing = true
    auditProc.command = ["bash", "-c", Model.buildAuditScript(root.effectiveProjects)]
    auditProc.running = true
  }

  Process {
    id: auditProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var scanned = Model.parseAuditOutput(String(text || ""), root.effectiveProjects)
        root.rawRepos = scanned
        root.refreshing = false
        root.lastRefreshedAt = Date.now()
        root.checkNewFindings(scanned)
      }
    }
  }

  // ---- Per-project rescan: re-runs just one repo's audit instead of every
  //      configured project. Reuses buildAuditScript/parseAuditOutput with
  //      a single-element projects array — the marker index it encodes is
  //      local to that array (always 0), which is fine since parsing that
  //      output only ever needs to line up with the same one-element array,
  //      not the repo's real position in the full list. Does NOT re-run
  //      discovery — rescanning one project shouldn't re-walk the
  //      filesystem, just re-audit whatever's already in effectiveProjects.
  property int singleRefreshIndex: -1

  function refreshOne(index) {
    if (index < 0 || index >= root.effectiveProjects.length) return
    if (root.anyProcRunning()) return
    root.singleRefreshIndex = index
    singleProc.command = ["bash", "-c", Model.buildAuditScript([root.effectiveProjects[index]])]
    singleProc.running = true
  }

  Process {
    id: singleProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var idx = root.singleRefreshIndex
        root.singleRefreshIndex = -1
        if (idx < 0 || idx >= root.effectiveProjects.length || idx >= root.rawRepos.length) return
        var updated = Model.parseAuditOutput(String(text || ""), [root.effectiveProjects[idx]])
        var next = root.rawRepos.slice()
        next[idx] = updated[0]
        root.rawRepos = next
        root.lastRefreshedAt = Date.now()
        root.checkNewFindings(updated)
      }
    }
  }

  // ---- Scan for new projects only: re-runs discovery against
  //      discoverRoots, but — unlike refresh(), which re-audits every
  //      configured project — audits only the ones not already in
  //      rawRepos. Existing repos' results are left untouched. This is
  //      what a large discoverRoots tree actually
  //      needs: refresh() re-checking every already-known repo's CVEs is
  //      the right thing on a timer/manual refresh, but "did I just clone
  //      something new" shouldn't have to pay for re-auditing everything
  //      else too.
  property string newProjectsStatus: ""
  property var pendingNewProjects: []

  function scanForNewProjects() {
    if (root.anyProcRunning()) return
    if (root.discoverRoots.length === 0) {
      root.newProjectsStatus = "No discoverRoots configured"
      return
    }
    root.newProjectsStatus = "Scanning for new projects…"
    newProjectsProc.command = ["bash", "-c", Model.buildDiscoveryScript(root.discoverRoots)]
    newProjectsProc.running = true
  }

  Process {
    id: newProjectsProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var knownPaths = {}
        for (var i = 0; i < root.rawRepos.length; i++) knownPaths[root.rawRepos[i].path] = true
        root.discoveredProjects = Model.parseDiscoveredProjects(String(text || ""))
        var fresh = []
        var merged = root.effectiveProjects
        for (var j = 0; j < merged.length; j++) {
          if (!knownPaths[merged[j].path]) fresh.push(merged[j])
        }
        if (fresh.length === 0) {
          root.newProjectsStatus = "No new projects found"
          return
        }
        root.newProjectsStatus = "Auditing " + fresh.length + " new project" + (fresh.length === 1 ? "" : "s") + "…"
        root.pendingNewProjects = fresh
        // Shows the newly found project(s) in the list right away, as
        // "pending", instead of only appearing once their own (separate,
        // possibly slow) audit script finishes.
        root.rawRepos = Model.buildPendingRepos(root.effectiveProjects, root.rawRepos)
        newAuditProc.command = ["bash", "-c", Model.buildAuditScript(fresh)]
        newAuditProc.running = true
      }
    }
  }

  Process {
    id: newAuditProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var fresh = root.pendingNewProjects
        root.pendingNewProjects = []
        var scanned = Model.parseAuditOutput(String(text || ""), fresh)

        // refreshOne/singleProc index a repo by its position in
        // effectiveProjects, so rawRepos must stay ordered the same way —
        // a newly discovered project can land anywhere within the
        // discovered segment (find's traversal order, not append order),
        // not necessarily at the end, so a plain concat here would
        // desync that index alignment for any refreshOne() called before
        // the next full refresh() rebuilds rawRepos from scratch anyway.
        var byPath = {}
        for (var i = 0; i < root.rawRepos.length; i++) byPath[root.rawRepos[i].path] = root.rawRepos[i]
        for (var j = 0; j < scanned.length; j++) byPath[scanned[j].path] = scanned[j]
        var merged = root.effectiveProjects
        var next = []
        for (var k = 0; k < merged.length; k++) {
          var p = byPath[merged[k].path]
          if (p) next.push(p)
        }
        root.rawRepos = next

        root.lastRefreshedAt = Date.now()
        root.newProjectsStatus = scanned.length + " new project" + (scanned.length === 1 ? "" : "s") + " found"
        root.checkNewFindings(scanned)
      }
    }
  }

  Timer {
    id: refreshTimer
    interval: Math.max(1, root.refreshMinutes) * 60 * 1000
    running: true
    repeat: root.refreshMinutes > 0
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  function copyFixCommand(command) {
    var text = String(command || "")
    if (text === "") return
    Quickshell.execDetached(["bash", "-c", "printf %s " + Util.shellQuote(text) + " | wl-copy"])
  }

  function openFindingUrl(url) {
    var text = String(url || "")
    if (text === "" || !root.bar) return
    root.bar.run("omarchy-launch-browser " + Util.shellQuote(text))
  }

  function statusLabel(repo) {
    if (repo.status === "pending") return "Waiting for first audit…"
    if (repo.status === "missing-path") return "Path does not exist — check this project's \"path\" in shell.json"
    if (repo.status === "missing-tool") return "'" + repo.tool + "' not found on PATH — install it to audit this repo"
    if (repo.status === "unrecognized") return "No recognized manifest (package.json / Cargo.toml / requirements.txt / pyproject.toml / go.mod / Gemfile.lock / *.csproj)"
    if (repo.status === "parse-error") return "Could not parse audit output"
    if (repo.status === "ok" && repo.findings.length === 0) return "No known vulnerabilities"
    return ""
  }

  // ---- In-panel settings form. Edits go through `bar.shell
  //      .updateEntryInline` — the same first-party mechanism the bar's own
  //      drag-to-reorder uses to persist a widget's inline shell.json
  //      settings — rather than a bespoke write of our own. `projects` and
  //      `discoverRoots` are edited as plain multi-line text (Model.js's
  //      parseProjectsText/parseRootsText do the conversion), not a dynamic
  //      per-row add/remove list — far less QML, and copy-paste friendly.
  property bool settingsOpen: false
  property string draftIcon: ""
  property int draftRefreshMinutes: 60
  property string draftDiscoverRootsText: ""
  property string draftProjectsText: ""
  property string settingsError: ""

  function openSettings() {
    root.draftIcon = Model.plainText(setting("icon", "🛡"))
    root.draftRefreshMinutes = root.refreshMinutes
    root.draftDiscoverRootsText = Model.rootsToText(root.discoverRoots)
    root.draftProjectsText = Model.projectsToText(root.projects)
    root.settingsError = ""
    root.newProjectsStatus = ""
    root.settingsOpen = true
  }

  function closeSettings() {
    root.settingsOpen = false
    root.settingsError = ""
  }

  function saveSettings() {
    if (!root.bar || !root.bar.shell || typeof root.bar.shell.updateEntryInline !== "function") {
      root.settingsError = "Can't save from here — bar.shell.updateEntryInline is unavailable."
      return
    }
    // Start from the full current settings object, not a blank one:
    // updateEntryInline replaces the widget's entire inline settings, so
    // any key this form doesn't manage (none today, but future-proofing)
    // would otherwise be silently dropped.
    var next = {}
    for (var k in root.settings) next[k] = root.settings[k]

    var icon = root.draftIcon.trim()
    if (icon === "") delete next.icon
    else next.icon = icon

    next.refreshIntervalMinutes = Math.max(0, root.draftRefreshMinutes || 0)
    next.discoverRoots = Model.parseRootsText(root.draftDiscoverRootsText)
    next.projects = Model.parseProjectsText(root.draftProjectsText)

    root.bar.shell.updateEntryInline(root.moduleName, next)
    root.closeSettings()
  }

  // Themed multi-line text box for the discoverRoots/projects fields —
  // plain TextEdit rather than the kit's TextField (single-line only), no
  // multi-line control exists in qs.Ui to reuse. Colors built only from
  // helpers already proven working elsewhere in this file (Qt.darker,
  // Util.alpha, Color.accent) rather than the kit's internal
  // Style.controlFill/Border.controlSpec, whose exact signatures aren't
  // independently verified here.
  component DepauditMultilineField: Rectangle {
    id: field
    property alias text: input.text
    property color fg: Color.foreground
    implicitHeight: Style.space(90)
    radius: Style.cornerRadius
    color: Util.alpha(field.fg, 0.06)
    border.color: input.activeFocus ? Color.accent : Util.alpha(field.fg, 0.25)
    border.width: 1
    clip: true

    Flickable {
      anchors.fill: parent
      anchors.margins: Style.space(6)
      contentWidth: width
      contentHeight: Math.max(height, input.implicitHeight)
      clip: true
      boundsBehavior: Flickable.StopAtBounds
      interactive: contentHeight > height

      TextEdit {
        id: input
        width: parent.width
        wrapMode: TextEdit.NoWrap
        color: field.fg
        selectByMouse: true
        selectionColor: Util.alpha(Color.accent, 0.35)
        font.family: Style.font.family
        font.pixelSize: Style.font.bodySmall
      }
    }
  }

  // One finding row — used by the repo detail view's paginated Repeater.
  // A `component` block can't see ids from the rest of this file (`root`
  // included), so everything it needs (colors, the copy/open-url/dismiss
  // actions) comes in as an explicit property rather than reaching out to
  // `root.*` directly, the way the rest of this file does.
  component DepauditFindingRow: Rectangle {
    id: findingItem
    property var finding: null
    property color fg: Color.foreground
    property string fontFam: Style.font.family
    property var copyFixFn: function(command) {}
    property var openUrlFn: function(url) {}

    height: findingCol.implicitHeight + Style.space(10)
    radius: Style.cornerRadius
    color: findingArea.containsMouse ? Style.hoverFillFor(findingItem.fg, Color.accent) : "transparent"

    // Background click target: anywhere on the row not over a more
    // specific control (the id/CVE link below) copies the fix command.
    // Declared before findingCol so the column's content — including the
    // id link's own MouseArea — stacks on top of this one for both
    // painting and hit-testing.
    MouseArea {
      id: findingArea
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: findingItem.copyFixFn(findingItem.finding.fixCommand)
    }

    Column {
      id: findingCol
      x: Style.space(6)
      y: Style.space(5)
      width: parent.width - Style.space(12)
      spacing: Style.space(2)

      Row {
        spacing: Style.space(8)

        Text {
          text: "[" + Model.severityLabel(findingItem.finding.severity) + "]"
          color: Model.severityColor(findingItem.finding.severity) || Qt.darker(findingItem.fg, 1.5)
          font.family: findingItem.fontFam
          font.pixelSize: Style.font.caption
          font.bold: true
        }

        Text {
          text: findingItem.finding.package + (findingItem.finding.fixedVersion
            ? ("  " + findingItem.finding.range + " → " + findingItem.finding.fixedVersion)
            : ("  " + findingItem.finding.range))
          color: findingItem.fg
          font.family: findingItem.fontFam
          font.pixelSize: Style.font.bodySmall
        }

        // ---- CVE (preferred) or native advisory id, opening the
        //      advisory's page in the browser on click. idArea sits on top
        //      of the row's background copy-fix area since this Text is a
        //      descendant of findingCol, declared after findingArea.
        Text {
          visible: findingItem.finding.id !== ""
          text: findingItem.finding.id
          color: idArea.containsMouse ? Color.accent : Qt.darker(Color.accent, 1.2)
          font.family: findingItem.fontFam
          font.pixelSize: Style.font.bodySmall
          font.underline: idArea.containsMouse

          MouseArea {
            id: idArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: findingItem.openUrlFn(findingItem.finding.url)
          }
        }
      }

      Text {
        visible: text !== ""
        text: findingItem.finding.title
        color: Qt.darker(findingItem.fg, 1.5)
        font.family: findingItem.fontFam
        font.pixelSize: Style.font.caption
        wrapMode: Text.WordWrap
        width: findingCol.width
      }

      Text {
        text: "Copy fix: " + findingItem.finding.fixCommand
        color: Color.accent
        font.family: findingItem.fontFam
        font.pixelSize: Style.font.caption
      }
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    centerOnBar: true
    focusTarget: keyCatcher
    // Wider/taller while a repo's detail view is open — that's the whole
    // point of it being a separate view rather than an inline expand: room
    // for the filter chips + a real page of findings without the popup
    // feeling cramped.
    contentWidth: panel.fittedContentWidth(Style.space(root.detailPath !== "" ? 860 : 600))
    contentHeight: panel.fittedContentHeight(bodyCol.implicitHeight, Style.space(root.detailPath !== "" ? 640 : 520))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      // While the settings form is open, every key (including "r"/Escape)
      // must reach its TextField/TextEdit normally instead of being
      // interpreted as a panel shortcut — same reasoning as any inline
      // editor elsewhere in this shell (Keys.priority: Keys.BeforeItem
      // otherwise intercepts before the field ever sees the keystroke).
      blocked: root.settingsOpen
      // Escape steps back out of the detail view first (it's a drill-down,
      // not a separate dismissable surface) rather than closing the whole
      // panel from under it.
      onCloseRequested: root.detailPath !== "" ? root.closeDetail() : root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) { if (t === "r" || t === "R") root.refresh() }

      Flickable {
        id: scroll
        anchors.fill: parent
        contentWidth: width
        contentHeight: bodyCol.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height

        Column {
          id: bodyCol
          width: scroll.width
          spacing: Style.space(14)

          // ---- Header: total + worst severity, refresh state, settings
          //      toggle. An Item (not a Row) for the same reason the
          //      repo-header below uses one: pinning the gear to the right
          //      edge while the left side's content is variable-width.
          Item {
            width: parent.width
            height: mainHeaderRow.implicitHeight

            Row {
              id: mainHeaderRow
              anchors.left: parent.left
              anchors.right: scanNewBtn.visible ? scanNewBtn.left : settingsBtn.left
              anchors.rightMargin: Style.space(8)
              spacing: Style.space(8)

              Text {
                text: root.total > 0
                  ? (root.total + " finding" + (root.total === 1 ? "" : "s") + " · worst: " + Model.severityLabel(root.worstSeverity))
                  : "No known dependency findings"
                color: root.fg
                font.family: root.fontFam
                font.pixelSize: Style.font.body
                font.bold: true
              }

              Text {
                visible: root.refreshing
                text: "refreshing…"
                color: Qt.darker(root.fg, 1.5)
                font.family: root.fontFam
                font.pixelSize: Style.font.caption
                font.italic: true
                anchors.verticalCenter: parent.verticalCenter
              }

              Text {
                visible: !root.refreshing && root.newProjectsStatus !== ""
                text: root.newProjectsStatus
                color: Qt.darker(root.fg, 1.5)
                font.family: root.fontFam
                font.pixelSize: Style.font.caption
                font.italic: true
                anchors.verticalCenter: parent.verticalCenter
              }
            }

            // Re-runs discovery and audits only newly found projects,
            // leaving already-scanned repos untouched — see
            // scanForNewProjects() below. Only meaningful (and shown) when
            // discoverRoots is actually configured; a bare `projects` list
            // has nothing for it to discover.
            Text {
              id: scanNewBtn
              visible: !root.settingsOpen && root.discoverRoots.length > 0
              anchors.right: settingsBtn.left
              anchors.rightMargin: Style.space(8)
              anchors.verticalCenter: mainHeaderRow.verticalCenter
              text: (newProjectsProc.running || newAuditProc.running) ? "…" : "🔎"
              color: scanNewBtnArea.containsMouse ? Color.accent : Qt.darker(root.fg, 1.3)
              font.family: root.fontFam
              font.pixelSize: Style.font.body

              MouseArea {
                id: scanNewBtnArea
                anchors.fill: parent
                anchors.margins: -Style.space(4)
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.scanForNewProjects()
              }
            }

            Text {
              id: settingsBtn
              anchors.right: parent.right
              anchors.verticalCenter: mainHeaderRow.verticalCenter
              text: root.settingsOpen ? "✕" : "⚙"
              color: settingsBtnArea.containsMouse ? Color.accent : Qt.darker(root.fg, 1.3)
              font.family: root.fontFam
              font.pixelSize: Style.font.body

              MouseArea {
                id: settingsBtnArea
                anchors.fill: parent
                anchors.margins: -Style.space(4)
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.settingsOpen ? root.closeSettings() : root.openSettings()
              }
            }
          }

          // Always visible regardless of state (settings open, empty,
          // populated) — a first-glance answer to "what does this even
          // audit", not buried in the README.
          Text {
            text: Model.supportedEcosystemsText()
            color: Qt.darker(root.fg, 1.5)
            font.family: root.fontFam
            font.pixelSize: Style.font.caption
          }

          // ---- Settings form — replaces the finding list while open.
          Column {
            visible: root.settingsOpen
            width: parent.width
            spacing: Style.space(10)

            Text {
              text: "Widget settings"
              color: root.fg
              font.family: root.fontFam
              font.pixelSize: Style.font.body
              font.bold: true
            }

            Text {
              visible: root.settingsError !== ""
              text: root.settingsError
              color: Model.severityColor("critical")
              font.family: root.fontFam
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              width: parent.width
            }

            Text {
              text: "Icon"
              color: Qt.darker(root.fg, 1.4)
              font.family: root.fontFam
              font.pixelSize: Style.font.caption
            }
            TextField {
              id: iconField
              width: parent.width
              text: root.draftIcon
              onTextChanged: root.draftIcon = text
            }

            NumberField {
              label: "Refresh interval (minutes, 0 = manual/rescan only)"
              from: 0
              to: 1440
              value: root.draftRefreshMinutes
              foreground: root.fg
              onModified: function(v) { root.draftRefreshMinutes = v }
            }

            Text {
              text: "Discover roots — one absolute directory per line"
              color: Qt.darker(root.fg, 1.4)
              font.family: root.fontFam
              font.pixelSize: Style.font.caption
            }
            DepauditMultilineField {
              id: rootsField
              width: parent.width
              fg: root.fg
              text: root.draftDiscoverRootsText
              onTextChanged: root.draftDiscoverRootsText = text
            }

            Text {
              text: "Projects — one per line: \"label | path\" or just \"path\""
              color: Qt.darker(root.fg, 1.4)
              font.family: root.fontFam
              font.pixelSize: Style.font.caption
            }
            DepauditMultilineField {
              id: projectsField
              width: parent.width
              fg: root.fg
              text: root.draftProjectsText
              onTextChanged: root.draftProjectsText = text
            }

            Row {
              spacing: Style.space(8)

              Button {
                text: "Save"
                bordered: true
                foreground: root.fg
                onClicked: root.saveSettings()
              }
              Button {
                text: "Cancel"
                bordered: true
                foreground: root.fg
                onClicked: root.closeSettings()
              }
            }
          }

          Text {
            visible: !root.settingsOpen && root.effectiveProjects.length === 0
            text: "No projects configured. Click the ⚙ above to add some, or\nedit this widget's entry in ~/.config/omarchy/shell.json —\nsee the plugin README."
            color: Qt.darker(root.fg, 1.5)
            font.family: root.fontFam
            font.pixelSize: Style.font.bodySmall
            font.italic: true
          }

          // ---- One row per configured repo, collapsed to just its header
          //      and severity-count summary — that's what keeps a long
          //      project list from being a wall of findings, and it
          //      answers "is this one a problem" without opening it.
          //      Click the header to open its findings in a dedicated
          //      detail view (see the Column below this Repeater, gated on
          //      root.detailPath) — a separate view rather than expanding
          //      inline, since a repo with a lot of findings made an
          //      inline expand genuinely slow. Click the rescan glyph to
          //      re-audit just this repo instead of every configured
          //      project.
          Repeater {
            model: (root.settingsOpen || root.detailPath !== "") ? [] : root.repos

            Column {
              id: repoSection
              required property var modelData
              required property int index
              width: bodyCol.width
              spacing: Style.space(6)

              readonly property var counts: Model.countBySeverity(modelData.findings)
              readonly property bool hasFindings: modelData.status === "ok" && modelData.findings.length > 0
              readonly property bool refreshingThis: root.singleRefreshIndex === index

              Rectangle {
                width: parent.width
                height: Style.spacing.hairline
                color: root.fg
                opacity: 0.12
              }

              // ---- Header: arrow + severity dot + label + path on the
              //      left, rescan glyph pinned to the right. The whole row
              //      opens the detail view — a hover background (same
              //      Style.hoverFillFor treatment finding rows use) plus an
              //      accent-colored, bolder arrow make that discoverable
              //      without hovering first to notice the cursor change.
              //      The rescan glyph is a descendant declared after the
              //      background MouseArea, so it stacks on top for
              //      hit-testing (same pattern the finding rows below use
              //      for their id/CVE link over the copy-fix background).
              Item {
                id: headerRow
                width: parent.width
                height: labelRow.implicitHeight + Style.space(8)

                Rectangle {
                  anchors.fill: parent
                  radius: Style.cornerRadius
                  color: headerArea.containsMouse ? Style.hoverFillFor(root.fg, Color.accent) : "transparent"
                }

                MouseArea {
                  id: headerArea
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.openDetail(repoSection.modelData.path)
                }

                // `headerLeft` is an Item, not a Row: a Row sizes itself to
                // its children's natural widths and won't shrink them, so
                // anchoring it between the chevron and the rescan glyph
                // wouldn't actually constrain (and elide) a long path — it
                // would just overflow past the rescan glyph. Packing the
                // fixed-size icons/label in their own inner Row and giving
                // the path Text real anchors (left of the inner row's
                // right edge, right at headerLeft's edge) is what makes
                // elide have a real width to work against.
                Item {
                  id: headerLeft
                  anchors.left: parent.left
                  anchors.leftMargin: Style.space(4)
                  anchors.right: rescanBtn.left
                  anchors.rightMargin: Style.space(8)
                  anchors.verticalCenter: parent.verticalCenter
                  height: labelRow.implicitHeight

                  Row {
                    id: labelRow
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(8)

                    Text {
                      text: "❯"
                      color: headerArea.containsMouse ? Color.accent : Qt.darker(root.fg, 1.3)
                      font.family: root.fontFam
                      font.pixelSize: Style.font.body
                      font.bold: true
                      anchors.verticalCenter: parent.verticalCenter
                    }

                    Rectangle {
                      width: Style.space(8)
                      height: Style.space(8)
                      radius: width / 2
                      anchors.verticalCenter: parent.verticalCenter
                      color: Model.severityColor(repoSection.modelData.worstSeverity) || Qt.darker(root.fg, 1.6)
                    }

                    Text {
                      text: repoSection.modelData.label
                      color: root.fg
                      font.family: root.fontFam
                      font.pixelSize: Style.font.body
                      font.bold: true
                    }
                  }

                  Text {
                    anchors.left: labelRow.right
                    anchors.leftMargin: Style.space(8)
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    text: repoSection.modelData.path
                    color: Qt.darker(root.fg, 1.6)
                    font.family: root.fontFam
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideMiddle
                  }
                }

                Text {
                  id: rescanBtn
                  anchors.right: parent.right
                  anchors.verticalCenter: headerLeft.verticalCenter
                  text: repoSection.refreshingThis ? "…" : "⟳"
                  color: rescanArea.containsMouse ? Color.accent : Qt.darker(root.fg, 1.3)
                  font.family: root.fontFam
                  font.pixelSize: Style.font.body

                  MouseArea {
                    id: rescanArea
                    anchors.fill: parent
                    anchors.margins: -Style.space(4)
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.refreshOne(repoSection.index)
                  }
                }
              }

              // ---- Severity-count summary, visible whether collapsed or
              //      expanded (it's the whole point of collapsing).
              Row {
                spacing: Style.space(6)
                visible: repoSection.hasFindings

                Repeater {
                  model: ["critical", "high", "moderate", "low", "unknown"]

                  Text {
                    required property string modelData
                    visible: repoSection.counts[modelData] > 0
                    text: repoSection.counts[modelData] + " " + Model.severityLabel(modelData)
                    color: Model.severityColor(modelData) || Qt.darker(root.fg, 1.5)
                    font.family: root.fontFam
                    font.pixelSize: Style.font.caption
                    font.bold: true
                  }
                }
              }

              Text {
                visible: root.statusLabel(repoSection.modelData) !== ""
                text: root.statusLabel(repoSection.modelData)
                color: Qt.darker(root.fg, 1.5)
                font.family: root.fontFam
                font.pixelSize: Style.font.bodySmall
                font.italic: true
                wrapMode: Text.WordWrap
                width: parent.width
              }

            }
          }

          // ---- Repo detail view: opened by clicking a repo above (see
          //      root.openDetail), replaces the repo list entirely rather
          //      than sitting alongside it — same "one screen, one job" as
          //      the settings form. Severity filter chips + pagination
          //      (root.detailPageSize per page) keep the number of finding
          //      delegates that ever exist at once small and constant,
          //      regardless of how many findings the repo actually has.
          Column {
            visible: !root.settingsOpen && root.detailPath !== ""
            width: parent.width
            spacing: Style.space(10)

            Item {
              width: parent.width
              height: detailBackRow.implicitHeight

              Row {
                id: detailBackRow
                anchors.left: parent.left
                anchors.right: detailRescanBtn.left
                anchors.rightMargin: Style.space(8)
                spacing: Style.space(10)

                Text {
                  text: "‹ Back"
                  color: detailBackArea.containsMouse ? Color.accent : Qt.darker(root.fg, 1.3)
                  font.family: root.fontFam
                  font.pixelSize: Style.font.body
                  anchors.verticalCenter: parent.verticalCenter

                  MouseArea {
                    id: detailBackArea
                    anchors.fill: parent
                    anchors.margins: -Style.space(4)
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.closeDetail()
                  }
                }

                Text {
                  text: root.detailRepo ? root.detailRepo.label : root.detailPath
                  color: root.fg
                  font.family: root.fontFam
                  font.pixelSize: Style.font.body
                  font.bold: true
                  anchors.verticalCenter: parent.verticalCenter
                }
              }

              Text {
                id: detailRescanBtn
                anchors.right: parent.right
                anchors.verticalCenter: detailBackRow.verticalCenter
                text: root.singleRefreshIndex === root.findEffectiveIndex(root.detailPath) && root.singleRefreshIndex !== -1 ? "…" : "⟳"
                color: detailRescanArea.containsMouse ? Color.accent : Qt.darker(root.fg, 1.3)
                font.family: root.fontFam
                font.pixelSize: Style.font.body

                MouseArea {
                  id: detailRescanArea
                  anchors.fill: parent
                  anchors.margins: -Style.space(4)
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.refreshOne(root.findEffectiveIndex(root.detailPath))
                }
              }
            }

            Text {
              visible: root.detailRepo !== null
              text: root.detailPath
              color: Qt.darker(root.fg, 1.6)
              font.family: root.fontFam
              font.pixelSize: Style.font.caption
              elide: Text.ElideMiddle
              width: parent.width
            }

            Text {
              visible: root.detailRepo === null
              text: "This project is no longer in the list."
              color: Qt.darker(root.fg, 1.5)
              font.family: root.fontFam
              font.pixelSize: Style.font.bodySmall
              font.italic: true
            }

            // ---- Severity filter chips, each labeled with how many of
            //      this repo's findings match, so a chip reading "0" is
            //      visibly not worth clicking.
            Flow {
              visible: root.detailRepo !== null
              width: parent.width
              spacing: Style.space(6)

              Repeater {
                model: Model.SEVERITY_FILTERS

                Rectangle {
                  id: chip
                  required property string modelData
                  readonly property int chipCount: chip.modelData === "all"
                    ? root.detailFiltered.length
                    : (root.detailAllCounts[chip.modelData] || 0)
                  readonly property bool active: root.detailSeverity === chip.modelData
                  width: chipLabel.implicitWidth + Style.space(16)
                  height: chipLabel.implicitHeight + Style.space(8)
                  radius: height / 2
                  color: chip.active ? Util.alpha(Color.accent, 0.25) : Util.alpha(root.fg, 0.08)
                  border.width: chip.active ? 1 : 0
                  border.color: Color.accent

                  Text {
                    id: chipLabel
                    anchors.centerIn: parent
                    text: Model.severityLabel(chip.modelData) + " (" + chip.chipCount + ")"
                    color: chip.active ? Color.accent : Qt.darker(root.fg, 1.3)
                    font.family: root.fontFam
                    font.pixelSize: Style.font.caption
                    font.bold: chip.active
                  }

                  MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.setDetailSeverity(chip.modelData)
                  }
                }
              }
            }

            Text {
              visible: root.detailRepo !== null && root.detailFiltered.length === 0
              text: root.detailSeverity === "all" ? "No findings." : "No " + Model.severityLabel(root.detailSeverity) + " findings."
              color: Qt.darker(root.fg, 1.5)
              font.family: root.fontFam
              font.pixelSize: Style.font.bodySmall
              font.italic: true
            }

            Repeater {
              model: root.detailRepo !== null ? root.detailPaged.items : []

              DepauditFindingRow {
                width: bodyCol.width
                finding: modelData
                fg: root.fg
                fontFam: root.fontFam
                copyFixFn: root.copyFixCommand
                openUrlFn: root.openFindingUrl
              }
            }

            // ---- Pager: only shown once there's more than one page —
            //      most repos with a handful of findings never need it.
            Row {
              visible: root.detailRepo !== null && root.detailPaged.pageCount > 1
              spacing: Style.space(14)

              Text {
                text: "‹ Prev"
                color: root.detailPaged.page > 0
                  ? (detailPrevArea.containsMouse ? Color.accent : root.fg)
                  : Qt.darker(root.fg, 1.8)
                font.family: root.fontFam
                font.pixelSize: Style.font.caption

                MouseArea {
                  id: detailPrevArea
                  anchors.fill: parent
                  anchors.margins: -Style.space(4)
                  enabled: root.detailPaged.page > 0
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.detailPage = root.detailPaged.page - 1
                }
              }

              Text {
                text: "Page " + (root.detailPaged.page + 1) + " of " + root.detailPaged.pageCount + " · " + root.detailPaged.total + " findings"
                color: Qt.darker(root.fg, 1.5)
                font.family: root.fontFam
                font.pixelSize: Style.font.caption
              }

              Text {
                text: "Next ›"
                color: root.detailPaged.page < root.detailPaged.pageCount - 1
                  ? (detailNextArea.containsMouse ? Color.accent : root.fg)
                  : Qt.darker(root.fg, 1.8)
                font.family: root.fontFam
                font.pixelSize: Style.font.caption

                MouseArea {
                  id: detailNextArea
                  anchors.fill: parent
                  anchors.margins: -Style.space(4)
                  enabled: root.detailPaged.page < root.detailPaged.pageCount - 1
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.detailPage = root.detailPaged.page + 1
                }
              }
            }
          }
        }
      }
    }
  }
}
