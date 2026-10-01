import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

AppDialog {
    id: dialog
    required property var service
    readonly property var setup: service.setup
    property bool populating: false
    property bool advanced: false
    ThemeTokens { id: colors; source: dialog.service.theme }
    theme: colors
    dismissible: false
    objectName: "serverSetupDialog"
    title: "Connect to your server"
    width: Math.min(560, parent.width - 32)
    function changed() { if (!populating && opened) service.settingsEdited(true) }
    onOpened: setup.read(config.text)
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
        id: scroll; clip: true; contentWidth: availableWidth
        implicitHeight: Math.min(form.implicitHeight, 510)
        ColumnLayout {
            id: form; width: scroll.availableWidth; spacing: 10
            Label { Layout.fillWidth: true; text: "Get the address and public key from your server’s operator."; color: colors.muted; font.pixelSize: 13; wrapMode: Text.WordWrap }
            Label { text: "Server address"; color: colors.ink; font.pixelSize: 13; Layout.topMargin: 10 }
            AppField { id: url; objectName: "serverUrl"; theme: colors; enabled: !dialog.setup.busy; Layout.fillWidth: true; placeholderText: "wss://chat.example"; Accessible.name: "Server address"; onTextChanged: dialog.changed() }
            Label { text: "Server public key"; color: colors.ink; font.pixelSize: 13; Layout.topMargin: 4 }
            AppField { id: pin; objectName: "serverPin"; theme: colors; enabled: !dialog.setup.busy; Layout.fillWidth: true; placeholderText: "64 hexadecimal characters"; maximumLength: 64; Accessible.name: "Server public key"; onTextChanged: dialog.changed() }
            Label { Layout.fillWidth: true; text: "This key verifies you’re connecting to the right server."; color: colors.muted; font.pixelSize: 12; wrapMode: Text.WordWrap }
            Label { text: "Display name · optional"; color: colors.ink; font.pixelSize: 13; Layout.topMargin: 4 }
            AppField { id: displayName; theme: colors; enabled: !dialog.setup.busy; Layout.fillWidth: true; placeholderText: "How people will see you"; maximumLength: 80; Accessible.name: "Display name, optional"; onTextChanged: dialog.changed() }
            Label { text: "Invite code · optional"; color: colors.ink; font.pixelSize: 13; Layout.topMargin: 4 }
            AppField { id: invite; theme: colors; enabled: !dialog.setup.busy; Layout.fillWidth: true; placeholderText: "If your server requires an invitation"; maximumLength: 128; echoMode: TextInput.Password; Accessible.name: "Invite code, optional"; onTextChanged: dialog.changed() }
            Label { Layout.fillWidth: true; text: "The server operator can read messages. Your existing settings are backed up before saving."; color: colors.muted; font.pixelSize: 12; wrapMode: Text.WordWrap; Layout.topMargin: 8 }
            AppButton { theme: colors; quiet: true; text: dialog.advanced ? "Hide configuration file" : "Choose configuration file…"; onClicked: dialog.advanced = !dialog.advanced }
            ColumnLayout {
                visible: dialog.advanced; Layout.fillWidth: true; spacing: 8
                Label { text: "Use the same file as your daemon."; color: colors.muted; font.pixelSize: 12 }
                AppField { id: config; objectName: "serverConfigPath"; theme: colors; Layout.fillWidth: true; placeholderText: "Default OmaChat configuration"; enabled: !dialog.setup.busy; onTextChanged: dialog.changed(); Accessible.name: "Daemon configuration file" }
                AppButton { theme: colors; text: "Load file / discard edits"; enabled: !dialog.setup.busy; onClicked: dialog.setup.read(config.text) }
            }
        }
    }
    footer: Item {
        implicitHeight: footerContent.implicitHeight + 32
        ColumnLayout {
            id: footerContent; anchors.fill: parent; anchors.margins: 16; spacing: 10
            Label { objectName: "setupError"; Layout.fillWidth: true; wrapMode: Text.WordWrap; visible: !!text; text: dialog.setup.error; textFormat: Text.PlainText; color: colors.warning; font.pixelSize: 13; Accessible.role: Accessible.AlertMessage }
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; visible: dialog.setup.restartRequired; text: "Settings saved. Restart OmaChat’s daemon to connect with these settings."; color: colors.accent; font.pixelSize: 13 }
            RowLayout {
                Layout.fillWidth: true
                AppButton { theme: colors; text: dialog.setup.restartRequired ? "Done" : "Cancel"; enabled: !dialog.setup.busy; onClicked: { dialog.service.settingsEdited(false); dialog.close() } }
                Item { Layout.fillWidth: true }
                AppButton { objectName: "saveServerSettings"; theme: colors; primary: true; text: dialog.setup.busy ? "Saving…" : "Save settings"; enabled: !dialog.setup.busy && !!dialog.setup.configRevision && config.text === dialog.setup.path && !!url.text.trim() && /^[0-9a-fA-F]{64}$/.test(pin.text.trim()); onClicked: dialog.setup.save({url:url.text.trim(), pinned_server_public_key:pin.text.trim(), display_name:displayName.text.trim(), invite_code:invite.text.trim()}) }
            }
        }
    }
}
