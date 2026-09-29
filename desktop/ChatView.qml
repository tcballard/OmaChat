import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "ChatState.js" as State
import "Contact.js" as Contact

Item {
    id: view
    required property var service
    property bool showChats: false
    readonly property bool narrow: width < 760
    readonly property var active: service.activeChat
    readonly property color surface: service.theme.background || "#17191e"
    readonly property color sidebar: Qt.tint(surface, "#0b808080")
    readonly property color ink: service.theme.foreground || "#eef0f5"
    readonly property color muted: Qt.tint(ink, Qt.rgba(surface.r, surface.g, surface.b, 0.3))
    readonly property color accent: service.theme.accent || "#a2dcc5"
    readonly property color line: Qt.tint(surface, Qt.rgba(ink.r, ink.g, ink.b, 0.18))
    readonly property bool light: surface.r + surface.g + surface.b > 1.5
    readonly property color warning: light ? "#87550c" : "#f0c889"
    readonly property color control: Qt.tint(surface, Qt.rgba(ink.r, ink.g, ink.b, 0.07))
    readonly property color hovered: Qt.tint(surface, Qt.rgba(ink.r, ink.g, ink.b, 0.12))
    readonly property color selected: Qt.tint(surface, Qt.rgba(accent.r, accent.g, accent.b, 0.16))

    // The two models reconcile in place so new events do not rebuild the timeline.
    ListModel { id: conversations }
    ListModel { id: messages }
    property string shownConversation: ""
    function reconcile(model, rows) {
        while (model.count > rows.length) model.remove(model.count - 1)
        for (var i = 0; i < rows.length; i++) {
            if (i < model.count) model.set(i, rows[i]); else model.append(rows[i])
        }
    }
    function sync() {
        var query = filter.text.toLowerCase()
        var rows = service.chats.filter(function(c) { return (c.title + " " + c.id).toLowerCase().indexOf(query) !== -1 })
        reconcile(conversations, rows.map(function(c) { return { cid: c.id, title: c.title, unread: c.unread, preview: c.draft ? "Draft · " + c.draft : (c.messages.length ? c.messages[c.messages.length - 1].text : "No messages yet") } }))
        var c = service.activeChat
        var changed = shownConversation !== (c ? c.id : "")
        var pinned = timeline.atYEnd || changed
        if (changed) messages.clear()
        shownConversation = c ? c.id : ""
        reconcile(messages, c ? c.messages : [])
        if (composer.text !== (c ? c.draft : "")) composer.text = c ? c.draft : ""
        if (pinned) Qt.callLater(function() { timeline.positionViewAtEnd() })
    }
    Component.onCompleted: sync()
    Connections { target: service; function onRevisionChanged() { view.sync() } }

    component Action : Button {
        id: action
        implicitHeight: 38
        leftPadding: 14; rightPadding: 14
        palette.buttonText: view.ink
        contentItem: Text { text: action.text; color: action.enabled ? view.ink : view.muted; font.pixelSize: 13; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter; textFormat: Text.PlainText }
        background: Rectangle { radius: 6; color: action.down ? view.selected : action.hovered ? view.hovered : view.control; border.color: action.activeFocus ? view.accent : view.line; border.width: action.activeFocus ? 2 : 1; opacity: action.enabled ? 1 : 0.6 }
    }
    component Field : TextField {
        color: view.ink; placeholderTextColor: view.muted
        selectByMouse: true; font.pixelSize: 14
        implicitHeight: 40; leftPadding: 10; rightPadding: 10
        background: Rectangle { color: view.surface; radius: 5; border.color: parent.activeFocus ? view.accent : view.line }
    }
    Rectangle { anchors.fill: parent; color: view.surface }
    RowLayout {
        anchors.fill: parent; spacing: 0
        Rectangle {
            Layout.fillHeight: true
            Layout.preferredWidth: view.narrow ? view.width : 280
            visible: !view.narrow || view.showChats || !view.active
            color: view.sidebar
            ColumnLayout {
                anchors.fill: parent; anchors.margins: 20; spacing: 16
                RowLayout {
                    Layout.fillWidth: true
                    Text { text: "OmaChat"; color: view.ink; font.pixelSize: 24; font.weight: Font.DemiBold; Layout.fillWidth: true }
                    Text { text: "PREVIEW"; color: view.accent; font.pixelSize: 10; font.letterSpacing: 1.5 }
                }
                RowLayout {
                    Layout.fillWidth: true
                    Action { text: "New message"; Layout.fillWidth: true; onClicked: { service.actionError = ""; dm.open() } }
                    Action { text: "Join"; onClicked: { service.actionError = ""; join.open(); service.request("list-rooms") } }
                }
                Field { id: filter; objectName: "conversationSearch"; Layout.fillWidth: true; placeholderText: "Find a conversation"; Accessible.name: "Find a conversation"; onTextChanged: view.sync() }
                Text { text: "CONVERSATIONS"; color: view.muted; font.pixelSize: 10; font.letterSpacing: 1.7 }
                ListView {
                    id: chatList
                    Layout.fillWidth: true; Layout.fillHeight: true
                    clip: true; spacing: 5; model: conversations
                    ScrollBar.vertical: ScrollBar {}
                    delegate: ItemDelegate {
                        id: chatRow
                        required property string cid
                        required property string title
                        required property string preview
                        required property int unread
                        width: chatList.width; height: 68
                        Accessible.name: title + (unread ? ", unread messages" : "")
                        onClicked: { service.select(cid); view.showChats = false; composer.forceActiveFocus() }
                        background: Rectangle { radius: 6; color: view.active && view.active.id === chatRow.cid ? view.selected : chatRow.hovered ? view.hovered : "transparent"; border.color: chatRow.activeFocus ? view.accent : "transparent" }
                        contentItem: ColumnLayout {
                            spacing: 6
                            RowLayout {
                                Text { text: chatRow.title; textFormat: Text.PlainText; color: view.ink; elide: Text.ElideRight; font.pixelSize: 14; font.weight: Font.DemiBold; Layout.fillWidth: true }
                                Text { text: "●"; visible: chatRow.unread > 0; color: view.accent; font.pixelSize: 10 }
                            }
                            Text { text: chatRow.preview; textFormat: Text.PlainText; color: view.muted; elide: Text.ElideRight; maximumLineCount: 1; font.pixelSize: 12; Layout.fillWidth: true }
                        }
                    }
                    Text { anchors.centerIn: parent; width: parent.width; visible: conversations.count === 0; text: filter.text ? "No matching conversations" : "Your conversations will appear here."; color: view.muted; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter }
                }
                Action { text: "My identity & connection"; Layout.fillWidth: true; onClicked: identity.open() }
            }
        }
        Rectangle { visible: !view.narrow; Layout.fillHeight: true; width: 1; color: view.line }
        ColumnLayout {
            Layout.fillWidth: true; Layout.fillHeight: true; spacing: 0
            visible: !view.narrow || (!!view.active && !view.showChats)
            Rectangle {
                Layout.fillWidth: true; implicitHeight: 84; color: view.surface
                RowLayout {
                    anchors.fill: parent; anchors.margins: 24; spacing: 14
                    Action { text: "Chats"; visible: view.narrow; onClicked: view.showChats = true }
                    ColumnLayout {
                        Layout.fillWidth: true; spacing: 5
                        Text { text: view.active ? view.active.title : "A place to talk."; textFormat: Text.PlainText; color: view.ink; font.pixelSize: 20; font.weight: Font.DemiBold; elide: Text.ElideRight; Layout.fillWidth: true }
                        Text { text: !view.active ? "People first. Agents when you need them." : view.active.id.indexOf("dm:") === 0 ? "Direct message · confirm the public key with your contact" : "Room · relay permissions apply; not an encrypted DM"; color: view.muted; font.pixelSize: 11; elide: Text.ElideRight; Layout.fillWidth: true }
                    }
                    Rectangle { width: 8; height: 8; radius: 4; color: service.ready ? view.accent : view.warning; Accessible.name: service.ready ? "Local daemon connected" : "Local daemon disconnected" }
                }
            }
            Rectangle { Layout.fillWidth: true; height: 1; color: view.line }
            Rectangle {
                Layout.fillWidth: true; implicitHeight: connectionText.implicitHeight + 20
                color: service.ready ? view.selected : Qt.tint(view.surface, Qt.rgba(view.warning.r, view.warning.g, view.warning.b, 0.12))
                Text { id: connectionText; anchors.fill: parent; anchors.margins: 10; text: service.notice; textFormat: Text.PlainText; color: service.ready ? view.accent : view.warning; font.pixelSize: 12; wrapMode: Text.Wrap }
            }
            Item {
                Layout.fillWidth: true; Layout.fillHeight: true
                ListView {
                    id: timeline
                    objectName: "timeline"
                    anchors.fill: parent; anchors.margins: 24
                    clip: true; spacing: 18; model: messages
                    boundsBehavior: Flickable.StopAtBounds
                    ScrollBar.vertical: ScrollBar {}
                    delegate: Column {
                        id: messageRow
                        required property string sender
                        required property string text
                        required property bool outgoing
                        required property string delivery
                        width: timeline.width; spacing: 6
                        Text { text: messageRow.outgoing ? "You" : State.shortKey(messageRow.sender); textFormat: Text.PlainText; color: messageRow.outgoing ? view.accent : view.ink; font.pixelSize: 12; font.weight: Font.DemiBold }
                        TextEdit { width: parent.width - 12; text: messageRow.text; textFormat: TextEdit.PlainText; readOnly: true; selectByMouse: true; wrapMode: TextEdit.Wrap; color: view.ink; font.pixelSize: 15; Accessible.name: messageRow.sender + ": " + messageRow.text }
                        Text { visible: messageRow.outgoing; text: State.deliveryLabel(messageRow.delivery); color: messageRow.delivery === "failed" ? view.warning : view.muted; font.pixelSize: 10 }
                    }
                }
                ColumnLayout {
                    anchors.centerIn: parent; width: Math.min(380, parent.width - 64); spacing: 16
                    visible: messages.count === 0
                    Text { text: view.active ? "Start the conversation." : "Make yourself at home."; color: view.ink; font.pixelSize: 25; font.weight: Font.DemiBold; Layout.fillWidth: true; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter }
                    Text { text: view.active ? "Write a message below. This preview keeps only the daemon’s recent history." : "Open a direct conversation with someone’s public key, or join a room on your configured relay."; color: view.muted; font.pixelSize: 14; Layout.fillWidth: true; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter }
                    Action { text: "New message"; visible: !view.active; Layout.alignment: Qt.AlignHCenter; onClicked: dm.open() }
                }
                Action { text: "Latest messages ↓"; anchors.right: parent.right; anchors.bottom: parent.bottom; anchors.margins: 16; visible: !timeline.atYEnd && messages.count > 0; onClicked: timeline.positionViewAtEnd() }
            }
            ColumnLayout {
                Layout.fillWidth: true; Layout.margins: 20; spacing: 10
                visible: !!view.active
                Text { visible: !!view.active && !!view.active.error; text: view.active ? view.active.error : ""; textFormat: Text.PlainText; color: view.warning; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                Action { visible: !!view.active && view.active.uncertain; text: "I checked — allow another send"; onClicked: service.reviewedUnknown() }
                Text { objectName: "draftStatus"; text: service.draftStatus; textFormat: Text.PlainText; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                ScrollView {
                    visible: service.draftConflict
                    Layout.fillWidth: true; Layout.preferredHeight: 70
                    TextArea { text: service.draftConflictText || "(Saved draft is empty)"; readOnly: true; selectByMouse: true; wrapMode: TextArea.Wrap; color: view.ink; Accessible.name: "Saved draft from another client" }
                }
                RowLayout {
                    visible: service.draftConflict
                    Action { text: "Keep my text"; onClicked: service.resolveDraft(true) }
                    Action { text: "Use saved text"; onClicked: service.resolveDraft(false) }
                }
                Action { visible: service.draftRecovered; text: "I checked — continue with this draft"; onClicked: service.reviewDraft() }
                Action { visible: service.draftError; text: "Retry draft recovery"; onClicked: service.retryDraft() }
                ScrollView {
                    Layout.fillWidth: true; Layout.preferredHeight: 106
                    TextArea {
                        id: composer
                        objectName: "composer"
                        placeholderText: service.ready ? "Write a message…" : "Draft a message while reconnecting…"
                        Accessible.name: "Message"
                        color: view.ink; placeholderTextColor: view.muted
                        wrapMode: TextArea.Wrap; selectByMouse: true
                        font.pixelSize: 15; padding: 12
                        background: Rectangle { color: view.control; radius: 7; border.color: composer.activeFocus ? view.accent : view.line }
                        onTextChanged: service.draft(text)
                        Keys.onPressed: function(event) {
                            if ((event.key === Qt.Key_Return || event.key === Qt.Key_Enter) && !(event.modifiers & Qt.ShiftModifier)) { service.send(); event.accepted = true }
                        }
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    Text { text: "Enter to send · Shift+Enter for a new line"; color: view.muted; font.pixelSize: 10; Layout.fillWidth: true; wrapMode: Text.WordWrap }
                    Text { text: State.utf8Length(composer.text) + "/4096"; color: State.utf8Length(composer.text) > 4096 ? view.warning : view.muted; font.pixelSize: 10 }
                    Action { objectName: "sendButton"; text: view.active && view.active.busy ? "Sending…" : "Send"; enabled: service.ready && service.draftCanSend && !!view.active && !view.active.busy && !view.active.uncertain && composer.text.trim().length > 0 && State.utf8Length(composer.text) <= 4096; onClicked: service.send() }
                }
            }
        }
    }
    component Sheet : Dialog {
        parent: Overlay.overlay
        anchors.centerIn: parent
        width: Math.min(500, view.width - 32)
        modal: true; focus: true; padding: 24
        palette.windowText: view.ink; palette.text: view.ink
        background: Rectangle { color: view.sidebar; border.color: view.line; radius: 10 }
    }
    Sheet {
        id: dm
        title: "New direct message"
        onOpened: { service.actionError = ""; peer.forceActiveFocus() }
        onClosed: { peer.clear(); service.actionError = "" }
        contentItem: ColumnLayout {
            spacing: 16
            Text { text: "Paste an npub, nprofile, nostr: contact link, or hexadecimal public key. Check the identity with your contact before sharing sensitive information."; color: view.muted; Layout.fillWidth: true; wrapMode: Text.WordWrap }
            Field { id: peer; objectName: "peerKey"; placeholderText: "Paste a contact link or public key"; Accessible.name: "Contact public key or link"; maximumLength: 5000; Layout.fillWidth: true; onAccepted: if (service.newDm(text)) { dm.close(); view.showChats = false; composer.forceActiveFocus() } }
            Text {
                property var contact: Contact.preview(peer.text)
                objectName: "contactPreview"
                text: contact.key ? contact.format + " · " + contact.key + (contact.hintsIgnored ? "\nRelay hints in this link are ignored; your configured relays are used." : "") : contact.error
                textFormat: Text.PlainText; color: contact.key ? view.accent : view.warning
                visible: text.length > 0; wrapMode: Text.WrapAnywhere; Layout.fillWidth: true
            }
            Text { text: service.actionError; textFormat: Text.PlainText; visible: text.length > 0; color: view.warning; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            RowLayout { Layout.alignment: Qt.AlignRight; Action { text: "Cancel"; onClicked: dm.close() } Action { text: "Open conversation"; onClicked: if (service.newDm(peer.text)) { dm.close(); view.showChats = false; composer.forceActiveFocus() } } }
        }
    }
    Sheet {
        id: join
        title: "Join a room"
        contentItem: ColumnLayout {
            spacing: 14
            Text { text: service.rooms.length ? "Choose a relay already configured in your daemon. A join request does not guarantee admission. Room messages are not end-to-end encrypted by this client." : "No room relays are configured. Follow desktop/README.md to configure the daemon, then restart it."; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            ComboBox { id: relay; Layout.fillWidth: true; model: service.rooms.map(function(r) { return r.relay }); Accessible.name: "Configured room relay" }
            Field { id: group; Layout.fillWidth: true; placeholderText: "Room ID"; Accessible.name: "Room ID"; maximumLength: 128 }
            Field { id: invitation; Layout.fillWidth: true; placeholderText: "Invite code (optional)"; Accessible.name: "Invite code"; maximumLength: 256; echoMode: TextInput.Password }
            Text { text: service.actionError; textFormat: Text.PlainText; visible: text.length > 0; color: view.warning; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            RowLayout { Layout.alignment: Qt.AlignRight; Action { text: "Close"; onClicked: join.close() } Action { text: service.actionBusy ? "Working…" : "Request to join"; enabled: service.ready && !service.actionBusy && service.rooms.length > 0 && group.text.trim().length > 0; onClicked: service.joinRoom(relay.currentText, group.text, invitation.text) } }
        }
        Connections { target: service; function onActionFinished(method) { if (method === "join-room" && join.opened) { join.close(); view.showChats = false } } }
    }
    Sheet {
        id: identity
        title: "My identity & connection"
        contentItem: ColumnLayout {
            spacing: 16
            Text { text: service.ready ? "Connected to the local daemon. This does not prove relay reachability or message delivery." : "Waiting for the daemon. Build PR #230 and start omachatd using the setup instructions."; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Text { text: "SHARE YOUR CONTACT LINK"; color: view.accent; font.pixelSize: 10; font.letterSpacing: 1 }
            TextArea { id: myLink; text: service.publicKey ? "nostr:" + Contact.npub(service.publicKey) : "Available after connecting"; textFormat: TextEdit.PlainText; readOnly: true; selectByMouse: true; color: view.ink; wrapMode: TextEdit.WrapAnywhere; Layout.fillWidth: true; Accessible.name: "My contact link" }
            Action { text: "Copy contact link"; enabled: service.publicKey.length === 64; onClicked: { myLink.selectAll(); myLink.copy(); myLink.deselect() } }
            Text { text: "This public link identifies this device, not a verified global handle. Copying it shares no private key. Drafts are kept only while this window is open; recent message history belongs to the daemon."; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Action { text: "Done"; Layout.alignment: Qt.AlignRight; onClicked: identity.close() }
        }
    }
    Shortcut { sequence: "Ctrl+N"; onActivated: dm.open() }
    Shortcut { sequence: "Ctrl+K"; onActivated: { view.showChats = true; filter.forceActiveFocus() } }
}
