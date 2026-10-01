import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: dialog
    required property var service
    readonly property var setup: service.setup
    property bool populating: false
    objectName: "relaySetupDialog"
    parent: Overlay.overlay
    anchors.centerIn: parent
    width: Math.min(560, parent.width - 24)
    height: Math.min(660, parent.height - 24)
    modal: true; focus: true
    closePolicy: Popup.NoAutoClose
    title: "Set up messaging"
    function urls(text) { return text.split(/\n/).map(function(s) { return s.trim() }).filter(function(s) { return !!s }) }
    function changed() { if (!populating && opened) service.settingsEdited(true) }
    onOpened: { setup.read(config.text) }
    Connections {
        target: dialog.setup
        function onLoaded() {
            dialog.populating = true
            config.text = dialog.setup.path
            dm.text = dialog.setup.dmRelays.join("\n")
            rooms.text = dialog.setup.roomRelays.join("\n")
            dialog.populating = false
            dialog.service.settingsEdited(false)
        }
    }
    contentItem: ScrollView {
        id: scroll
        clip: true
        contentWidth: availableWidth
        ColumnLayout {
            width: scroll.availableWidth; spacing: 12
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; text: "1. Choose the config used by your daemon. If you start it with --config, select that same file here." }
            TextField { id: config; objectName: "relayConfigPath"; Layout.fillWidth: true; placeholderText: "Default OmaChat configuration"; enabled: !dialog.setup.busy; onTextChanged: dialog.changed(); Accessible.name: "Daemon configuration file" }
            Button { text: "Load file / discard unapplied edits"; enabled: !dialog.setup.busy; onClicked: dialog.setup.read(config.text) }
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; text: "2. Enter relays you operate or have permission to use, one URL per line. Saving a URL does not verify reachability or protocol support. The daemon refuses to start while a private-message relay cannot be authenticated; correct or remove the URL here and restart it again." }
            Label { text: "Private messages · NIP-17 inbox relays" }
            TextArea { id: dm; objectName: "dmRelayUrls"; Layout.fillWidth: true; Layout.preferredHeight: 80; wrapMode: TextEdit.Wrap; placeholderText: "wss://…"; enabled: !dialog.setup.busy; onTextChanged: dialog.changed(); Accessible.name: "Private message relay URLs" }
            Label { text: "Rooms · NIP-29 relays (optional)" }
            TextArea { id: rooms; objectName: "roomRelayUrls"; Layout.fillWidth: true; Layout.preferredHeight: 80; wrapMode: TextEdit.Wrap; placeholderText: "wss://…"; enabled: !dialog.setup.busy; onTextChanged: dialog.changed(); Accessible.name: "Room relay URLs" }
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; text: "Room messages are not end-to-end encrypted DMs. Existing settings are preserved, with a private backup before replacement. Empty lists disable that transport on the next daemon start." }
            Label { objectName: "setupError"; Layout.fillWidth: true; wrapMode: Text.WordWrap; visible: !!text; text: dialog.setup.error }
            Label { Layout.fillWidth: true; wrapMode: Text.WrapAnywhere; visible: dialog.setup.restartRequired; text: "3. Settings saved. Restart the daemon using this configuration, then reconnect. This screen does not restart it.\n" + (dialog.setup.backup ? "Backup: " + dialog.setup.backup : "") }
            Button { objectName: "saveRelaySettings"; text: dialog.setup.busy ? "Working…" : "Save relay settings"; enabled: !dialog.setup.busy && !!dialog.setup.configRevision && config.text === dialog.setup.path; onClicked: dialog.setup.save(dialog.urls(dm.text), dialog.urls(rooms.text)) }
            Button { text: "Close / discard unapplied edits"; enabled: !dialog.setup.busy; onClicked: { dialog.service.settingsEdited(false); dialog.close() } }
        }
    }
}
