import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: dialog
    required property var service
    readonly property var setup: service.setup
    property bool populating: false
    objectName: "serverSetupDialog"
    parent: Overlay.overlay
    anchors.centerIn: parent
    width: Math.min(560, parent.width - 24)
    height: Math.min(660, parent.height - 24)
    modal: true; focus: true
    closePolicy: Popup.NoAutoClose
    title: "Set up messaging"
    function changed() { if (!populating && opened) service.settingsEdited(true) }
    onOpened: { setup.read(config.text) }
    Connections {
        target: dialog.setup
        function onLoaded() {
            dialog.populating = true
            config.text = dialog.setup.path
            url.text = dialog.setup.hosted.url || ""
            pin.text = dialog.setup.hosted.pinned_server_public_key || ""
            displayName.text = dialog.setup.hosted.display_name || ""
            invite.text = dialog.setup.hosted.invite_code || ""
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
            TextField { id: config; objectName: "serverConfigPath"; Layout.fillWidth: true; placeholderText: "Default OmaChat configuration"; enabled: !dialog.setup.busy; onTextChanged: dialog.changed(); Accessible.name: "Daemon configuration file" }
            Button { text: "Load file / discard unapplied edits"; enabled: !dialog.setup.busy; onClicked: dialog.setup.read(config.text) }
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; text: "2. Enter your server URL and the public key supplied by its operator. The operator can read messages. Saving does not test the connection." }
            TextField { id: url; enabled: !dialog.setup.busy; Layout.fillWidth: true; placeholderText: "wss://chat.example"; Accessible.name: "Server URL"; onTextChanged: dialog.changed() }
            TextField { id: pin; enabled: !dialog.setup.busy; Layout.fillWidth: true; placeholderText: "Server public key (64 hex characters)"; Accessible.name: "Pinned server public key"; onTextChanged: dialog.changed() }
            TextField { id: displayName; enabled: !dialog.setup.busy; Layout.fillWidth: true; placeholderText: "Display name (optional)"; Accessible.name: "Display name"; onTextChanged: dialog.changed() }
            TextField { id: invite; enabled: !dialog.setup.busy; Layout.fillWidth: true; placeholderText: "Invite code (optional)"; echoMode: TextInput.Password; Accessible.name: "Invite code"; onTextChanged: dialog.changed() }
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; text: "Saving replaces retired transport settings with this server configuration. A private backup is created before replacement." }
            Label { objectName: "setupError"; Layout.fillWidth: true; wrapMode: Text.WordWrap; visible: !!text; text: dialog.setup.error }
            Label { Layout.fillWidth: true; wrapMode: Text.WrapAnywhere; visible: dialog.setup.restartRequired; text: "3. Settings saved. Restart the daemon using this configuration, then reconnect. This screen does not restart it.\n" + (dialog.setup.backup ? "Backup: " + dialog.setup.backup : "") }
            Button { objectName: "saveServerSettings"; text: dialog.setup.busy ? "Working…" : "Save server settings"; enabled: !dialog.setup.busy && !!dialog.setup.configRevision && config.text === dialog.setup.path; onClicked: dialog.setup.save({url:url.text.trim(), pinned_server_public_key:pin.text.trim(), display_name:displayName.text.trim(), invite_code:invite.text.trim()}) }
            Button { text: "Close / discard unapplied edits"; enabled: !dialog.setup.busy; onClicked: { dialog.service.settingsEdited(false); dialog.close() } }
        }
    }
}
