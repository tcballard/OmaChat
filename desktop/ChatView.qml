import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "ChatState.js" as State

Item {
    id: view
    required property var service
    property bool showChats: false
    readonly property bool narrow: width < 760
    readonly property var active: service.activeChat
    // The conversation object is mutated in place and reused across revisions, so
    // bindings must read the revision explicitly or they never refresh (Qt 6.10).
    readonly property bool activeBusy: { service.revision; return !!active && !!active.busy }
    readonly property bool activeUncertain: { service.revision; return !!active && !!active.uncertain }
    readonly property string activeError: { service.revision; return active && active.error ? active.error : "" }
    readonly property string activeTitle: { service.revision; return active ? active.title : "" }
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
        rows.sort(function(a,b) { return (a.workspaceId || "").localeCompare(b.workspaceId || "") || a.title.localeCompare(b.title) })
        reconcile(conversations, rows.map(function(c) { var ws = (service.workspaces || []).find(function(w) { return w.workspace_id === c.workspaceId }); return { section: ws ? ws.name : "Direct messages", cid: c.id, title: c.title, unread: c.unread, preview: c.draft ? "Draft · " + c.draft : (c.messages.length ? c.messages[c.messages.length - 1].text : "No messages yet") } }))
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
                }
                Field { id: filter; objectName: "conversationSearch"; Layout.fillWidth: true; placeholderText: "Find a conversation"; Accessible.name: "Find a conversation"; onTextChanged: view.sync() }
                Text { text: "CONVERSATIONS"; color: view.muted; font.pixelSize: 10; font.letterSpacing: 1.7 }
                ListView {
                    id: chatList
                    Layout.fillWidth: true; Layout.fillHeight: true
                    clip: true; spacing: 5; model: conversations
                    section.property: "section"
                    section.delegate: Text { required property string section; text: section; color: view.accent; font.pixelSize: 12; padding: 6; textFormat: Text.PlainText }
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
                                Text { text: String(chatRow.unread); visible: chatRow.unread > 0; color: view.accent; font.pixelSize: 10 }
                            }
                            Text { text: chatRow.preview; textFormat: Text.PlainText; color: view.muted; elide: Text.ElideRight; maximumLineCount: 1; font.pixelSize: 12; Layout.fillWidth: true }
                        }
                    }
                    Text { anchors.centerIn: parent; width: parent.width; visible: conversations.count === 0; text: filter.text ? "No matching conversations" : "Your conversations will appear here."; color: view.muted; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter }
                }
                Action { objectName: "openHostedAdmin"; text: "Workspaces"; visible: !!service.hostedConnected; Layout.fillWidth: true; onClicked: { service.actionError = ""; admin.open(); service.refreshHosted() } }
                Action { objectName: "openServerSetup"; text: "Set up messaging"; Layout.fillWidth: true; onClicked: serverSetup.open() }
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
                        Text { text: view.active ? view.activeTitle : "A place to talk."; textFormat: Text.PlainText; color: view.ink; font.pixelSize: 20; font.weight: Font.DemiBold; elide: Text.ElideRight; Layout.fillWidth: true }
                        Text { text: !view.active ? "Your team, connected." : "The server operator can read messages"; color: view.muted; font.pixelSize: 11; elide: Text.ElideRight; Layout.fillWidth: true }
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
                        Text { visible: messageRow.outgoing; text: State.deliveryLabel(messageRow.delivery, !!view.active && view.active.id.indexOf("hosted:") === 0); color: messageRow.delivery === "failed" ? view.warning : view.muted; font.pixelSize: 10 }
                    }
                }
                ColumnLayout {
                    anchors.centerIn: parent; width: Math.min(380, parent.width - 64); spacing: 16
                    visible: messages.count === 0
                    Text { text: view.active ? "Start the conversation." : "Make yourself at home."; color: view.ink; font.pixelSize: 25; font.weight: Font.DemiBold; Layout.fillWidth: true; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter }
                    Text { text: view.active ? "Write a message below. This preview keeps only the daemon’s recent history." : "Open a direct conversation by @handle, or choose a workspace channel."; color: view.muted; font.pixelSize: 14; Layout.fillWidth: true; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter }
                    Action { text: "New message"; visible: !view.active; Layout.alignment: Qt.AlignHCenter; onClicked: dm.open() }
                }
                Action { text: "Latest messages ↓"; anchors.right: parent.right; anchors.bottom: parent.bottom; anchors.margins: 16; visible: !timeline.atYEnd && messages.count > 0; onClicked: timeline.positionViewAtEnd() }
            }
            ColumnLayout {
                Layout.fillWidth: true; Layout.margins: 20; spacing: 10
                visible: !!view.active
                RowLayout {
                    visible: !!view.active && view.active.id.indexOf("hosted:") === 0
                    Action { objectName: "olderHostedHistory"; text: "Earlier messages"; enabled: !!service.hostedConnected && !!view.active && view.active.hasOlder !== false; onClicked: service.loadHistory(true) }
                    Action { text: "Latest messages"; enabled: !!service.hostedConnected; onClicked: service.loadHistory(false) }
                }
                Text { objectName: "sendError"; visible: view.activeError.length > 0; text: view.activeError; textFormat: Text.PlainText; color: view.warning; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                Action { objectName: "allowResend"; visible: view.activeUncertain; text: "I checked — allow another send"; onClicked: service.reviewedUnknown() }
                Text { objectName: "draftStatus"; text: service.draftStatus; textFormat: Text.PlainText; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                ScrollView {
                    visible: service.draftConflict
                    Layout.fillWidth: true; Layout.preferredHeight: 70
                    TextArea { text: service.draftConflictText || "(Saved draft is empty)"; readOnly: true; selectByMouse: true; wrapMode: TextArea.Wrap; color: view.ink; padding: 10; Accessible.name: "Saved draft from another client"; background: Rectangle { color: view.control; radius: 6; border.color: view.line } }
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
                    Action { objectName: "sendButton"; text: view.activeBusy ? "Sending…" : "Send"; enabled: service.ready && service.draftCanSend && !!view.active && !view.activeBusy && !view.activeUncertain && composer.text.trim().length > 0 && State.utf8Length(composer.text) <= 4096; onClicked: service.send() }
                }
            }
        }
    }
    component Sheet : Dialog {
        id: sheet
        parent: Overlay.overlay
        header: Label { text: sheet.title; color: view.ink; font.pixelSize: 17; font.weight: Font.DemiBold; leftPadding: 24; rightPadding: 24; topPadding: 20; bottomPadding: 4; background: null }
        anchors.centerIn: parent
        width: Math.min(500, view.width - 32)
        modal: true; focus: true; padding: 24
        palette.windowText: view.ink; palette.text: view.ink
        background: Rectangle { color: view.sidebar; border.color: view.line; radius: 10 }
    }
    Sheet {
        id: dm
        Connections { target: service; function onActionFinished(method) { if (method === "hosted-open-dm") { dm.close(); view.showChats = false } } }
        title: "New direct message"
        onOpened: { service.actionError = ""; peer.forceActiveFocus() }
        onClosed: { peer.clear(); service.actionError = "" }
        contentItem: ColumnLayout {
            spacing: 16
            Text { text: "Enter a handle on your configured server. The server operator can read messages."; color: view.muted; Layout.fillWidth: true; wrapMode: Text.WordWrap }
            Field { id: peer; objectName: "peerKey"; placeholderText: "@handle"; Accessible.name: "Server handle"; maximumLength: 5000; Layout.fillWidth: true; onAccepted: if (service.newDm(text)) { dm.close(); view.showChats = false; composer.forceActiveFocus() } }

            Text { text: service.actionError; textFormat: Text.PlainText; visible: text.length > 0; color: view.warning; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            RowLayout { Layout.alignment: Qt.AlignRight; Action { text: "Cancel"; onClicked: dm.close() } Action { text: "Open conversation"; onClicked: if (service.newDm(peer.text)) { dm.close(); view.showChats = false; composer.forceActiveFocus() } } }
        }
    }
    Sheet {
        id: identity
        title: "My identity & connection"
        contentItem: ScrollView {
            id: identityScroll
            implicitHeight: Math.min(identityColumn.implicitHeight, view.height - 140)
            contentWidth: availableWidth
            ColumnLayout {
            id: identityColumn; width: identityScroll.availableWidth
            spacing: 16
            Text { text: service.ready ? "Connected to the local daemon. Check the server status below." : "Waiting for the daemon. Start omachatd using the setup instructions."; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Text { objectName: "hostedTrust"; visible: !!service.hosted && service.hosted.state !== "unconfigured" && service.hosted.state !== "disabled"; text: "Hosted server: " + (service.ready ? ((service.hosted || {}).state || "not configured") : "unknown — daemon disconnected") + "\n" + ((service.hosted || {}).url || "") + "\nThe operator can read messages on this server."; textFormat: Text.PlainText; color: view.warning; wrapMode: Text.WrapAnywhere; Layout.fillWidth: true }
            Field { id: hostedHandle; visible: !!service.hostedConnected && !(service.hosted || {}).handle; placeholderText: "Choose a hosted handle"; Layout.fillWidth: true; maximumLength: 32 }
            Action { text: "Claim hosted handle"; visible: !!service.hostedConnected && !(service.hosted || {}).handle; enabled: !service.actionBusy && hostedHandle.text.trim().length > 0; onClicked: service.request("hosted-claim-handle", {handle:hostedHandle.text.trim().replace(/^@/, "")}) }
            Text { text: (service.hosted || {}).handle ? "Hosted handle: @" + service.hosted.handle : ""; color: view.ink; textFormat: Text.PlainText }
            Text { text: service.actionError; visible: text.length > 0; color: view.warning; textFormat: Text.PlainText; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Text { text: "SHARE YOUR HANDLE"; color: view.accent; font.pixelSize: 10; font.letterSpacing: 1 }
            TextArea { id: myLink; text: service.hosted.handle ? "@" + service.hosted.handle : "Claim a handle below"; textFormat: TextEdit.PlainText; readOnly: true; selectByMouse: true; color: view.ink; wrapMode: TextEdit.WrapAnywhere; padding: 10; Layout.fillWidth: true; Accessible.name: "My server handle"; background: Rectangle { color: view.control; radius: 6; border.color: view.line } }
            Action { text: "Copy handle"; enabled: !!service.hosted.handle; onClicked: { myLink.selectAll(); myLink.copy(); myLink.deselect() } }
            Text { text: "This handle identifies your account on this server. Saved drafts and recent message history belong to the daemon. Unsaved edits remain in this window."; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Action { text: "Done"; Layout.alignment: Qt.AlignRight; onClicked: identity.close() }
            }
        }
    }
    Sheet {
        id: admin; title: "Hosted workspaces"
        onOpened: { adminResult.text = ""; workspaceName.forceActiveFocus() }
        Connections { target: service; function onActionFinished(method) {
            if (method === "hosted-create-workspace") { adminResult.text = "Workspace created."; workspaceName.clear() }
            else if (method === "hosted-create-channel") { adminResult.text = "Channel created."; channelName.clear() }
            else if (method === "hosted-add-member") { adminResult.text = "Member added."; memberHandle.clear() }
        } }
        contentItem: ScrollView {
            id: adminScroll
            implicitHeight: Math.min(adminColumn.implicitHeight, view.height - 140)
            contentWidth: availableWidth
            ColumnLayout {
            id: adminColumn; width: adminScroll.availableWidth
            spacing: 12
            Text { text: "Create a workspace, or manage one you own. The server verifies ownership for every change."; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Field { id: workspaceName; objectName: "workspaceName"; placeholderText: "New workspace name"; maximumLength: 64; Layout.fillWidth: true }
            Action { text: "Create workspace"; enabled: !!service.hostedConnected && !service.actionBusy && workspaceName.text.trim().length > 0; onClicked: service.administer("hosted-create-workspace", "", workspaceName.text) }
            ComboBox { id: owned; objectName: "ownedWorkspace"; Layout.fillWidth: true; model: (service.workspaces || []).filter(function(w) { return w.role === "owner" }); textRole: "name"; valueRole: "workspace_id"; Accessible.name: "Workspace you own" }
            Field { id: channelName; placeholderText: "New channel name"; maximumLength: 64; Layout.fillWidth: true }
            Action { text: "Create channel"; enabled: !!service.hostedConnected && !service.actionBusy && owned.count > 0 && channelName.text.trim().length > 0; onClicked: service.administer("hosted-create-channel", owned.currentValue, channelName.text) }
            Field { id: memberHandle; placeholderText: "Member @handle"; maximumLength: 32; Layout.fillWidth: true }
            Action { text: "Add member"; enabled: !!service.hostedConnected && !service.actionBusy && owned.count > 0 && memberHandle.text.trim().length > 0; onClicked: service.administer("hosted-add-member", owned.currentValue, memberHandle.text) }
            Text { id: adminResult; color: view.accent; textFormat: Text.PlainText; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Text { text: service.actionBusy ? "Working…" : service.actionError; color: view.warning; textFormat: Text.PlainText; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Action { text: "Close"; onClicked: admin.close() }
            }
        }
    }
    ServerSetup { id: serverSetup; service: view.service }
    Shortcut { sequence: "Ctrl+N"; onActivated: dm.open() }
    Shortcut { sequence: "Ctrl+K"; onActivated: { view.showChats = true; filter.forceActiveFocus() } }
}
