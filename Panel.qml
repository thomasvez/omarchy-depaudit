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

  // shell.json edits hot-reload `settings`/`projects`, but nothing else
  // reacts to that on its own — without this, editing the projects list
  // would sit idle until the next timer tick (up to refreshMinutes later)
  // instead of auditing the newly added/changed repos right away.
  onProjectsChanged: Qt.callLater(root.refresh)

  // Recurring re-audit cadence; 0 disables the recurring timer (still runs
  // once on startup/open) for anyone who wants manual/middle-click-only.
  readonly property int refreshMinutes: Math.max(0, parseInt(setting("refreshIntervalMinutes", 60), 10) || 0)

  property var repos: []
  property bool refreshing: false
  property double lastRefreshedAt: 0

  readonly property var summary: Model.aggregate(root.repos)
  readonly property int total: summary.total
  readonly property string worstSeverity: summary.worstSeverity

  // Collapsed/expanded state per repo, keyed by path (stable across a
  // refresh even though `repos` itself is a freshly-built array each time).
  // Every repo starts collapsed — that's the whole point of this map, so a
  // long project list doesn't dump every finding on screen at once; the
  // severity-count row below the header covers "is this one a problem"
  // without expanding it.
  property var expandedPaths: ({})

  function isExpanded(path) {
    return root.expandedPaths[path] === true
  }

  function toggleExpanded(path) {
    // Reassign a new object rather than mutate in place — `expandedPaths`
    // is a plain `property var`, and QML only fires change notifications
    // (which `isExpanded` bindings depend on to update) on reassignment.
    var next = {}
    for (var k in root.expandedPaths) next[k] = root.expandedPaths[k]
    next[path] = !root.expandedPaths[path]
    root.expandedPaths = next
  }

  function refresh() {
    if (root.projects.length === 0) {
      root.repos = []
      return
    }
    // Guards against auditProc too: both it and singleProc write into
    // `root.repos` on completion (one wholesale, one by index), so letting
    // a bulk and a single-project refresh run concurrently risks one
    // overwriting the other's result with stale data.
    if (auditProc.running || singleProc.running) return
    root.refreshing = true
    auditProc.command = ["bash", "-c", Model.buildAuditScript(root.projects)]
    auditProc.running = true
  }

  Process {
    id: auditProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.repos = Model.parseAuditOutput(String(text || ""), root.projects)
        root.refreshing = false
        root.lastRefreshedAt = Date.now()
      }
    }
  }

  // ---- Per-project rescan: re-runs just one repo's audit instead of every
  //      configured project. Reuses buildAuditScript/parseAuditOutput with
  //      a single-element projects array — the marker index it encodes is
  //      local to that array (always 0), which is fine since parsing that
  //      output only ever needs to line up with the same one-element array,
  //      not the repo's real position in the full list.
  property int singleRefreshIndex: -1

  function refreshOne(index) {
    if (index < 0 || index >= root.projects.length) return
    if (auditProc.running || singleProc.running) return
    root.singleRefreshIndex = index
    singleProc.command = ["bash", "-c", Model.buildAuditScript([root.projects[index]])]
    singleProc.running = true
  }

  Process {
    id: singleProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var idx = root.singleRefreshIndex
        root.singleRefreshIndex = -1
        if (idx < 0 || idx >= root.projects.length || idx >= root.repos.length) return
        var updated = Model.parseAuditOutput(String(text || ""), [root.projects[idx]])
        var next = root.repos.slice()
        next[idx] = updated[0]
        root.repos = next
        root.lastRefreshedAt = Date.now()
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
    if (repo.status === "missing-tool") return "'" + repo.tool + "' not found on PATH — install it to audit this repo"
    if (repo.status === "unrecognized") return "No recognized manifest (package.json / Cargo.toml / requirements.txt / pyproject.toml / go.mod / Gemfile.lock / *.csproj)"
    if (repo.status === "parse-error") return "Could not parse audit output"
    if (repo.status === "ok" && repo.findings.length === 0) return "No known vulnerabilities"
    return ""
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    centerOnBar: true
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(420))
    contentHeight: panel.fittedContentHeight(bodyCol.implicitHeight, Style.space(520))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
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

          // ---- Header: total + worst severity, refresh state.
          Row {
            width: parent.width
            spacing: Style.space(8)

            Text {
              text: root.total > 0
                ? (root.total + " finding" + (root.total === 1 ? "" : "s") + " · worst: " + root.worstSeverity)
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
          }

          Text {
            visible: root.projects.length === 0
            text: "No projects configured. Add a \"projects\" array to this widget's\nentry in ~/.config/omarchy/shell.json — see the plugin README."
            color: Qt.darker(root.fg, 1.5)
            font.family: root.fontFam
            font.pixelSize: Style.font.bodySmall
            font.italic: true
          }

          // ---- One collapsible section per configured repo. Collapsed by
          //      default: the severity-count row right under the header is
          //      what keeps a long project list from being a wall of
          //      findings — it answers "is this one a problem" without
          //      expanding it. Click the header to expand for the full
          //      finding list; click the rescan glyph to re-audit just this
          //      repo instead of every configured project.
          Repeater {
            model: root.repos

            Column {
              id: repoSection
              required property var modelData
              required property int index
              width: bodyCol.width
              spacing: Style.space(6)

              readonly property bool expanded: root.isExpanded(modelData.path)
              readonly property var counts: Model.countBySeverity(modelData.findings)
              readonly property bool hasFindings: modelData.status === "ok" && modelData.findings.length > 0
              readonly property bool refreshingThis: root.singleRefreshIndex === index

              Rectangle {
                width: parent.width
                height: Style.spacing.hairline
                color: root.fg
                opacity: 0.12
              }

              // ---- Header: chevron + severity dot + label + path on the
              //      left, rescan glyph pinned to the right. The whole row
              //      is the expand/collapse click target; the rescan glyph
              //      is a descendant declared after that background
              //      MouseArea, so it stacks on top for hit-testing (same
              //      pattern the finding rows below use for their id/CVE
              //      link over the copy-fix background).
              Item {
                id: headerRow
                width: parent.width
                height: labelRow.implicitHeight

                MouseArea {
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.toggleExpanded(repoSection.modelData.path)
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
                  anchors.right: rescanBtn.left
                  anchors.rightMargin: Style.space(8)
                  height: labelRow.implicitHeight

                  Row {
                    id: labelRow
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(8)

                    Text {
                      text: repoSection.expanded ? "▾" : "▸"
                      color: Qt.darker(root.fg, 1.4)
                      font.family: root.fontFam
                      font.pixelSize: Style.font.caption
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
                    text: repoSection.counts[modelData] + " " + modelData
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

              // ---- Findings for this repo — only rendered when expanded.
              Repeater {
                model: repoSection.expanded ? repoSection.modelData.findings : []

                Rectangle {
                  id: findingItem
                  required property var modelData
                  readonly property var finding: modelData
                  width: repoSection.width
                  height: findingCol.implicitHeight + Style.space(10)
                  radius: Style.cornerRadius
                  color: findingArea.containsMouse ? Style.hoverFillFor(root.fg, Color.accent) : "transparent"

                  // Background click target: anywhere on the row not over a
                  // more specific control (the id/CVE link below) copies the
                  // fix command. Declared before findingCol so the column's
                  // content — including the id link's own MouseArea — stacks
                  // on top of this one for both painting and hit-testing.
                  MouseArea {
                    id: findingArea
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.copyFixCommand(findingItem.finding.fixCommand)
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
                        text: "[" + findingItem.finding.severity + "]"
                        color: Model.severityColor(findingItem.finding.severity) || Qt.darker(root.fg, 1.5)
                        font.family: root.fontFam
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }

                      Text {
                        text: findingItem.finding.package + (findingItem.finding.fixedVersion
                          ? ("  " + findingItem.finding.range + " → " + findingItem.finding.fixedVersion)
                          : ("  " + findingItem.finding.range))
                        color: root.fg
                        font.family: root.fontFam
                        font.pixelSize: Style.font.bodySmall
                      }

                      // ---- CVE (preferred) or native advisory id, opening
                      //      the advisory's page in the browser on click.
                      //      idArea sits on top of the row's background
                      //      copy-fix area since this Text is a descendant
                      //      of findingCol, declared after findingArea.
                      Text {
                        visible: findingItem.finding.id !== ""
                        text: findingItem.finding.id
                        color: idArea.containsMouse ? Color.accent : Qt.darker(Color.accent, 1.2)
                        font.family: root.fontFam
                        font.pixelSize: Style.font.bodySmall
                        font.underline: idArea.containsMouse

                        MouseArea {
                          id: idArea
                          anchors.fill: parent
                          hoverEnabled: true
                          cursorShape: Qt.PointingHandCursor
                          onClicked: root.openFindingUrl(findingItem.finding.url)
                        }
                      }
                    }

                    Text {
                      visible: text !== ""
                      text: findingItem.finding.title
                      color: Qt.darker(root.fg, 1.5)
                      font.family: root.fontFam
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.WordWrap
                      width: findingCol.width
                    }

                    Text {
                      text: "Copy fix: " + findingItem.finding.fixCommand
                      color: Color.accent
                      font.family: root.fontFam
                      font.pixelSize: Style.font.caption
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
