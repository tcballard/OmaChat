import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root
    required property var service
    color: "#17191e"
    property string draft: ""
    property string peer: ""
    property string handle: ""
    property string relayText: service.relays.join("\n")

    onServiceChanged: relayText = service.relays.join("\n")
    Connections {
        target: service
        function onRevisionChanged() { if (!relayEdit.activeFocus) root.relayText = service.relays.join("\n") }
    }

    RowLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 12
        ColumnLayout {
            Layout.preferredWidth: 280
            Layout.fillHeight: true
            Label { text: "Your npub"; color: "#9aa0a6" }
            Label { text: service.npub || "No key yet"; color: "#f3f4f6"; wrapMode: Text.Wrap; Layout.fillWidth: true }
            Button { text: "Copy npub"; onClicked: service.copyNpub(); enabled: service.npub.length > 0 }
            Label { text: "Handle"; color: "#9aa0a6" }
            TextField { Layout.fillWidth: true; placeholderText: "alice"; text: root.handle; onTextChanged: root.handle = text; color: "#f3f4f6" }
            RowLayout {
                Button { text: "Claim"; onClicked: service.claim(root.handle) }
                Button { text: "Bind npub"; onClicked: service.bind() }
            }
            Label { text: "Contacts"; color: "#9aa0a6" }
            ListView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: service.contacts
                delegate: ItemDelegate {
                    required property var modelData
                    width: ListView.view.width
                    text: modelData.display || modelData.npub || modelData.pubkey
                    onClicked: service.select(modelData.pubkey)
                    highlighted: modelData.pubkey === service.selectedKey
                }
            }
            TextField { Layout.fillWidth: true; placeholderText: "npub1… or name@domain"; text: root.peer; onTextChanged: root.peer = text; color: "#f3f4f6" }
            Button { text: "Add contact"; onClicked: { service.addContact(root.peer); root.peer = "" } }
            Label { text: "Relays"; color: "#9aa0a6" }
            TextArea {
                id: relayEdit
                Layout.fillWidth: true
                Layout.preferredHeight: 72
                text: root.relayText
                onTextChanged: root.relayText = text
                color: "#f3f4f6"
                wrapMode: TextEdit.NoWrap
            }
            Button { text: "Save relays"; onClicked: service.saveRelays(root.relayText) }
        }
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Label { text: service.notice || service.actionError; color: service.actionError ? "#f2b8b5" : "#9aa0a6"; wrapMode: Text.Wrap; Layout.fillWidth: true }
            ListView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: service.messages
                delegate: Label {
                    required property var modelData
                    width: ListView.view.width
                    wrapMode: Text.Wrap
                    color: "#f3f4f6"
                    text: (modelData.outgoing ? "you: " : (modelData.sender || "peer") + ": ") + modelData.text
                }
            }
            RowLayout {
                Layout.fillWidth: true
                TextField {
                    id: composer
                    Layout.fillWidth: true
                    placeholderText: "Message"
                    color: "#f3f4f6"
                    onAccepted: { service.send(text); text = "" }
                }
                Button { text: "Send"; onClicked: { service.send(composer.text); composer.text = "" } }
            }
        }
    }
}
