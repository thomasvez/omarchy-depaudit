import QtQuick
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

// Aggregated dependency-audit badge: a shield icon plus a vulnerability
// count across every configured project, color-coded by worst severity.
// Left click opens the per-repo breakdown; middle click re-runs every
// project's audit; right click sends the same summary as a notification,
// so the count is glanceable without opening the panel at all.
BarWidget {
  id: root
  moduleName: "io.github.thomasvez.depaudit"

  // Sanitized because WidgetButton's internal Text uses AutoText, which
  // would rich-text-parse a crafted setting.
  readonly property string icon: Model.plainText(setting("icon", "🛡"))

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
  }

  function refresh() {
    if (panelLoader.item && panelLoader.item.refresh) panelLoader.item.refresh()
  }

  function togglePanel() {
    if (panelLoader.item && panelLoader.item.toggle) panelLoader.item.toggle()
  }

  // Shape contract for shell.summon/hide/toggle routing (Bar.findPanelWidget
  // requires open/close/opened on the bar-widget root).
  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false

  function open() {
    if (panelLoader.item && panelLoader.item.openFromHotkey) panelLoader.item.openFromHotkey()
  }

  function close() {
    if (panelLoader.item && panelLoader.item.close) panelLoader.item.close()
  }

  // Forwarded so this widget can stand in for the panel as the bar's popout
  // identity: Bar.requestPopout prefers closeForPopoutSwitch over close, and
  // KeyboardPanel reads popoutSwitchClosing back off its owner.
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

  function closeForPopoutSwitch() {
    if (panelLoader.item) panelLoader.item.closeForPopoutSwitch()
  }

  // The panel owns the actual audit Process/Timer and keeps running it in
  // the background regardless of whether its popup surface is open (the
  // Loader below is always active) — the bar badge just reads its result.
  readonly property int total: panelLoader.item ? panelLoader.item.total : 0
  readonly property string worstSeverity: panelLoader.item ? panelLoader.item.worstSeverity : "none"
  readonly property color severityTint: {
    var hex = Model.severityColor(root.worstSeverity)
    return hex ? Qt.color(hex) : (root.bar ? root.bar.barForeground : Color.foreground)
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  IpcHandler {
    target: "io.github.thomasvez.depaudit"

    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.togglePanel() }
    function refresh(): void { root.refresh() }
  }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.total > 0 ? (root.icon + " " + root.total) : root.icon
    foreground: root.severityTint
    tooltipText: root.total > 0
      ? (root.total + " dependency finding" + (root.total === 1 ? "" : "s") + " — worst: " + root.worstSeverity)
      : "No known dependency findings"

    onPressed: function(b) {
      if (!root.bar) return
      if (b === Qt.RightButton)
        root.bar.run("omarchy-notification-send " + Util.shellQuote(Model.notificationSummary(root.total, root.worstSeverity)))
      else if (b === Qt.MiddleButton) root.refresh()
      else root.togglePanel()
    }
  }
}
