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

  function refresh() {
    if (root.projects.length === 0) {
      root.repos = []
      return
    }
    if (auditProc.running) return
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

  function statusLabel(repo) {
    if (repo.status === "pending") return "Waiting for first audit…"
    if (repo.status === "missing-tool") return "'" + repo.tool + "' not found on PATH — install it to audit this repo"
    if (repo.status === "unrecognized") return "No recognized manifest (package.json / Cargo.toml / requirements.txt / pyproject.toml / go.mod)"
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

          // ---- One section per configured repo.
          Repeater {
            model: root.repos

            Column {
              id: repoSection
              required property var modelData
              width: bodyCol.width
              spacing: Style.space(6)

              Rectangle {
                width: parent.width
                height: Style.spacing.hairline
                color: root.fg
                opacity: 0.12
              }

              Row {
                spacing: Style.space(8)

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

                Text {
                  text: repoSection.modelData.path
                  color: Qt.darker(root.fg, 1.6)
                  font.family: root.fontFam
                  font.pixelSize: Style.font.caption
                  anchors.verticalCenter: parent.verticalCenter
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

              // ---- Findings for this repo.
              Repeater {
                model: repoSection.modelData.findings

                Rectangle {
                  id: findingItem
                  required property var modelData
                  readonly property var finding: modelData
                  width: repoSection.width
                  height: findingCol.implicitHeight + Style.space(10)
                  radius: Style.cornerRadius
                  color: findingArea.containsMouse ? Style.hoverFillFor(root.fg, Color.accent) : "transparent"

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

                  MouseArea {
                    id: findingArea
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.copyFixCommand(findingItem.finding.fixCommand)
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
