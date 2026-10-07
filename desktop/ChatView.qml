import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "ChatState.js" as State

Item {
    id: view
    required property var service
    property bool showChats: false
    readonly property bool narrow: width < 760
    readonly property bool compact: width < 1080
    readonly property int pageInset: narrow ? colors.spaceMedium : colors.spaceLarge
    readonly property var active: service.activeChat
    // The conversation object is mutated in place and reused across revisions, so
    // bindings must read the revision explicitly or they never refresh (Qt 6.10).
    readonly property bool activeBusy: { service.revision; return !!active && !!active.busy }
    readonly property bool activeUncertain: { service.revision; return !!active && !!active.uncertain }
    readonly property string activeError: { service.revision; return active && active.error ? active.error : "" }
    readonly property string activeTitle: { service.revision; return active ? active.title : "" }
    ThemeTokens { id: colors; source: service.theme }
    readonly property color surface: colors.surface
    readonly property color sidebar: colors.panel
    readonly property color ink: colors.ink
    readonly property color muted: colors.muted
    readonly property color accent: colors.accent
    readonly property color line: colors.line
    readonly property color warning: colors.warning
    readonly property color control: colors.control
    readonly property color hovered: colors.hover
    readonly property color selected: colors.selected
    readonly property bool needsSetup: service.ready && (!service.hosted.state || service.hosted.state === "disabled" || service.hosted.state === "unconfigured")
    readonly property string connectionLabel: !service.ready ? "Reconnecting…" : needsSetup ? "Set up your server" : service.hostedConnected ? "Connected" : "Server offline"

    readonly property bool draftNeedsReview: service.draftConflict || service.draftRecovered || service.draftError || activeUncertain
    readonly property string composerState: activeBusy ? "Sending…" : draftNeedsReview ? "Review draft" : !service.ready || !service.hostedConnected ? "Offline draft" : !service.draftCanSend ? "Loading draft…" : composer.text.length ? "Draft" : "Ready to write"

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
        reconcile(conversations, rows.map(function(c) { var ws = (service.workspaces || []).find(function(w) { return w.workspace_id === c.workspaceId }); return { section: ws ? ws.name : "Direct messages", cid: c.id, title: c.title, unread: c.unread, channel: !!c.workspaceId, preview: c.draft ? "Draft · " + c.draft : (c.messages.length ? c.messages[c.messages.length - 1].text : "No messages yet") } }))
        var c = service.activeChat
        var changed = shownConversation !== (c ? c.id : "")
        var pinned = timeline.followLatest || changed
        if (changed) timeline.followLatest = true
        if (changed) messages.clear()
        shownConversation = c ? c.id : ""
        reconcile(messages, c ? c.messages : [])
        if (composer.text !== (c ? c.draft : "")) composer.text = c ? c.draft : ""
        if (pinned) Qt.callLater(function() { timeline.positionViewAtEnd() })
    }
    Component.onCompleted: sync()
    Connections { target: service; function onRevisionChanged() { view.sync() } function onWorkspacesChanged() { view.sync() } }

    component Action : AppButton { theme: colors }
    component Field : AppField { theme: colors }
    Rectangle { anchors.fill: parent; color: view.surface }
    RowLayout {
        anchors.fill: parent; spacing: 0
        Rectangle {
            Layout.fillHeight: true
            Layout.preferredWidth: view.narrow ? view.width : view.compact ? colors.sidebarCompactWidth : colors.sidebarWidth
            visible: !view.narrow || view.showChats || !view.active
            color: view.sidebar
            ColumnLayout {
                anchors.fill: parent; anchors.margins: view.compact ? colors.spaceMedium : colors.spaceLarge; spacing: colors.spaceMedium
                RowLayout {
                    Layout.fillWidth: true
                    Text { text: "OmaChat"; color: view.ink; font.pixelSize: 24; font.weight: Font.DemiBold; Layout.fillWidth: true }

                }
                RowLayout {
                    Layout.fillWidth: true
                    Action { text: "New message"; primary: true; Layout.fillWidth: true; enabled: !!service.hostedConnected; onClicked: { service.actionError = ""; dm.open() } }
                }
                RowLayout {
                    Layout.fillWidth: true; spacing: colors.spaceSmall
                    Field { id: filter; objectName: "conversationSearch"; Layout.fillWidth: true; placeholderText: "Find a conversation"; Accessible.name: "Find a conversation"; onTextChanged: view.sync(); Keys.onEscapePressed: clear() }
                    Action { objectName: "clearConversationSearch"; text: "Clear"; quiet: true; visible: filter.text.length > 0; Accessible.name: "Clear conversation search"; onClicked: { filter.clear(); filter.forceActiveFocus() } }
                }
                Text { text: "CONVERSATIONS"; color: view.muted; font.pixelSize: 11; font.letterSpacing: 1.2 }
                ListView {
                    id: chatList
                    objectName: "conversationList"
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
                        required property bool channel
                        width: chatList.width; height: 72
                        leftPadding: 14; rightPadding: 10
                        Accessible.name: (channel ? "Channel " : "Direct message ") + title + (unread ? ", " + unread + " unread messages" : "")
                        onClicked: { service.select(cid); view.showChats = false; composer.forceActiveFocus() }
                        background: Rectangle {
                            radius: colors.radiusControl
                            color: view.active && view.active.id === chatRow.cid ? view.selected : chatRow.hovered ? view.hovered : "transparent"
                            border.color: chatRow.activeFocus ? view.accent : "transparent"
                            Rectangle { width: 3; radius: 1; anchors.left: parent.left; anchors.top: parent.top; anchors.bottom: parent.bottom; anchors.topMargin: 12; anchors.bottomMargin: 12; color: view.accent; visible: !!view.active && view.active.id === chatRow.cid }
                        }
                        contentItem: ColumnLayout {
                            spacing: 6
                            RowLayout {
                                Text { text: chatRow.channel ? "#" : "@"; color: view.muted; font.pixelSize: colors.textBody; Accessible.ignored: true }
                                Text { text: chatRow.title.replace(chatRow.channel ? /^#/ : /^@/, ""); textFormat: Text.PlainText; color: view.ink; elide: Text.ElideRight; font.pixelSize: 14; font.weight: Font.DemiBold; Layout.fillWidth: true }
                                Rectangle { visible: chatRow.unread > 0; implicitWidth: Math.max(24, unreadLabel.implicitWidth + 12); implicitHeight: 24; radius: colors.radiusControl; color: view.accent
                                    Text { id: unreadLabel; anchors.centerIn: parent; text: chatRow.unread > 99 ? "99+" : String(chatRow.unread); color: colors.primaryInk; font.pixelSize: colors.textCaption; font.weight: Font.DemiBold }
                                }
                            }
                            Text { text: chatRow.preview; textFormat: Text.PlainText; color: view.muted; elide: Text.ElideRight; maximumLineCount: 1; font.pixelSize: 12; Layout.fillWidth: true }
                        }
                    }
                    Text { anchors.centerIn: parent; width: parent.width; visible: conversations.count === 0; text: filter.text ? "No matching conversations" : "Your conversations will appear here."; color: view.muted; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter }
                }
                Rectangle { Layout.fillWidth: true; height: 1; color: view.line }
                Action { objectName: "openHostedAdmin"; text: "Workspaces"; visible: !!service.hostedConnected; Layout.fillWidth: true; onClicked: { service.actionError = ""; admin.open(); service.refreshHosted() } }
                Action { objectName: "openServerSetup"; quiet: true; text: "Set up messaging"; Layout.fillWidth: true; onClicked: serverSetup.open() }
                Action { objectName: "openIdentity"; text: "My identity & connection"; quiet: true; Layout.fillWidth: true; onClicked: identity.open() }
            }
        }
        Rectangle { visible: !view.narrow; Layout.fillHeight: true; width: 1; color: view.line }
        ColumnLayout {
            Layout.fillWidth: true; Layout.fillHeight: true; spacing: 0
            visible: !view.narrow || (!!view.active && !view.showChats)
            Rectangle {
                Layout.fillWidth: true; implicitHeight: view.narrow ? 84 : 92; color: view.surface
                RowLayout {
                    anchors.fill: parent; anchors.margins: view.pageInset; spacing: colors.spaceSmall
                    Action { text: "Chats"; visible: view.narrow; onClicked: view.showChats = true }
                    ColumnLayout {
                        Layout.fillWidth: true; spacing: 5
                        Text { text: view.active ? view.activeTitle : "Conversations"; textFormat: Text.PlainText; color: view.ink; font.pixelSize: colors.textHeading; font.weight: Font.DemiBold; elide: Text.ElideRight; Layout.fillWidth: true }
                        Text { text: view.narrow ? view.connectionLabel : !view.active ? "Choose a channel or direct message" : "Messages are visible to the server operator"; color: view.muted; font.pixelSize: 11; elide: Text.ElideRight; Layout.fillWidth: true }
                    }
                    RowLayout {
                        spacing: 7
                        Rectangle { visible: !view.narrow; width: 6; height: 6; radius: 3; color: service.hostedConnected ? view.accent : view.warning }
                        Text { objectName: "connectionStatus"; text: view.connectionLabel; color: service.hostedConnected ? view.muted : view.warning; font.pixelSize: 12; visible: !view.narrow }
                    }
                }
            }
            Rectangle { Layout.fillWidth: true; height: 1; color: view.line }
            Rectangle {
                Layout.fillWidth: true; implicitHeight: statusRow.implicitHeight + 20
                visible: !service.hostedConnected || (!!service.notice && service.notice !== "Connected to local daemon")
                color: view.selected
                RowLayout {
                    id: statusRow; anchors.fill: parent; anchors.margins: 10
                    Text { id: connectionText; Layout.fillWidth: true; text: view.needsSetup ? "Connect to a server to start chatting." : !service.ready ? "Reconnecting to OmaChat. Your draft stays here." : !service.hostedConnected ? "Server offline. You can keep writing; sending resumes when connected." : service.notice; textFormat: Text.PlainText; color: view.ink; font.pixelSize: 13; wrapMode: Text.Wrap }
                    Action { text: "Set up"; visible: view.needsSetup; onClicked: serverSetup.open() }
                }
            }
            Item {
                Layout.fillWidth: true; Layout.fillHeight: true
                ListView {
                    id: timeline
                    objectName: "timeline"
                    property bool followLatest: true
                    onContentYChanged: if (moving) followLatest = atYEnd
                    onMovementEnded: followLatest = atYEnd
                    onHeightChanged: if (followLatest) Qt.callLater(function() { timeline.positionViewAtEnd() })
                    onContentHeightChanged: if (followLatest) Qt.callLater(function() { timeline.positionViewAtEnd() })
                    anchors.top: parent.top; anchors.bottom: parent.bottom; anchors.horizontalCenter: parent.horizontalCenter
                    anchors.topMargin: colors.spaceMedium; anchors.bottomMargin: colors.spaceMedium
                    width: Math.min(parent.width - view.pageInset * 2, colors.readingWidth)
                    clip: true; spacing: 22; model: messages
                    boundsBehavior: Flickable.StopAtBounds
                    ScrollBar.vertical: ScrollBar {}
                    header: Item {
                        width: timeline.width; height: view.active && messages.count ? 52 : 0; visible: height > 0
                        RowLayout {
                            anchors.left: parent.left; spacing: colors.spaceSmall
                            Action { objectName: "olderHostedHistory"; text: "Earlier messages"; quiet: true; enabled: !!service.hostedConnected && !!view.active && view.active.hasOlder !== false; onClicked: { timeline.followLatest = false; service.loadHistory(true) } }
                            Action { text: "Back to latest"; quiet: true; enabled: !!service.hostedConnected; onClicked: { timeline.followLatest = true; service.loadHistory(false); timeline.positionViewAtEnd() } }
                        }
                    }

                    delegate: Column {
                        id: messageRow
                        required property string sender
                        required property string text
                        required property bool outgoing
                        required property string delivery
                        width: timeline.width; spacing: 7
                        Text { text: messageRow.outgoing ? "You" : State.shortKey(messageRow.sender); textFormat: Text.PlainText; color: messageRow.outgoing ? view.accent : view.ink; font.pixelSize: 12; font.weight: Font.DemiBold }
                        TextEdit { width: parent.width; text: messageRow.text; textFormat: TextEdit.PlainText; readOnly: true; selectByMouse: true; wrapMode: TextEdit.Wrap; color: view.ink; selectionColor: colors.accent; selectedTextColor: colors.primaryInk; font.pixelSize: colors.textBody; Accessible.name: messageRow.sender + ": " + messageRow.text }
                        Text { visible: messageRow.outgoing; text: State.deliveryLabel(messageRow.delivery, !!view.active && view.active.id.indexOf("hosted:") === 0); color: messageRow.delivery === "failed" ? view.warning : view.muted; font.pixelSize: 11 }
                    }
                }
                ColumnLayout {
                    anchors.centerIn: parent; width: Math.min(380, parent.width - 64); spacing: 16
                    visible: messages.count === 0
                    Text { text: view.active ? "No messages yet" : view.needsSetup ? "Connect to your server" : "Choose a conversation"; color: view.ink; font.pixelSize: 25; font.weight: Font.DemiBold; Layout.fillWidth: true; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter }
                    Text { text: view.active ? "Write the first message to " + view.activeTitle + ". Your server keeps the conversation history." : view.needsSetup ? "Get the server address and public key from your operator to begin." : "Select a workspace channel or start a direct message with someone on your server."; color: view.muted; font.pixelSize: 14; Layout.fillWidth: true; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter }
                    Action { text: view.needsSetup ? "Connect to a server" : "New message"; primary: true; visible: !view.active; enabled: view.needsSetup || !!service.hostedConnected; Layout.alignment: Qt.AlignHCenter; onClicked: view.needsSetup ? serverSetup.open() : dm.open() }
                }
                Action { text: "Latest messages ↓"; anchors.right: parent.right; anchors.bottom: parent.bottom; anchors.margins: 16; visible: !timeline.atYEnd && messages.count > 0; onClicked: { timeline.followLatest = true; timeline.positionViewAtEnd() } }
            }
            Rectangle {
                id: composerFrame; objectName: "composerFrame"
                Layout.fillWidth: true; Layout.maximumWidth: colors.readingWidth
                Layout.alignment: Qt.AlignHCenter; Layout.margins: view.pageInset
                implicitHeight: composerContents.implicitHeight + colors.spaceMedium * 2
                visible: !!view.active; color: view.control; radius: colors.radiusPanel
                border.color: composer.activeFocus ? view.accent : view.line
                Rectangle { width: 3; anchors.left: parent.left; anchors.top: parent.top; anchors.bottom: parent.bottom; anchors.topMargin: colors.spaceMedium; anchors.bottomMargin: colors.spaceMedium; color: view.draftNeedsReview || !service.hostedConnected ? view.warning : view.accent }
                ColumnLayout {
                    id: composerContents; anchors.fill: parent; anchors.margins: colors.spaceMedium; spacing: colors.spaceSmall
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "MESSAGE"; color: view.muted; font.pixelSize: colors.textCaption; font.letterSpacing: 1; Layout.fillWidth: true }
                        Text { objectName: "composerState"; text: view.composerState; color: view.draftNeedsReview ? view.warning : view.muted; font.pixelSize: colors.textCaption }
                    }
                    ScrollView {
                        id: recoveryScroll; objectName: "draftRecovery"
                        Layout.fillWidth: true; Layout.preferredHeight: Math.min(recoveryColumn.implicitHeight, view.narrow ? 112 : 160)
                        visible: !!view.activeError || view.draftNeedsReview || !service.ready || !service.draftCanSend || composer.text.length > 0; contentWidth: availableWidth; clip: true
                        ColumnLayout {
                            id: recoveryColumn; width: recoveryScroll.availableWidth; spacing: colors.spaceSmall
                                Text { objectName: "sendError"; visible: view.activeError.length > 0; text: view.activeError; textFormat: Text.PlainText; color: view.warning; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                                Action { objectName: "allowResend"; visible: view.activeUncertain; text: "I checked — allow another send"; onClicked: service.reviewedUnknown() }
                                Text { objectName: "draftStatus"; visible: !!text && (composer.text.length > 0 || view.draftNeedsReview || !service.ready || !service.draftCanSend); text: service.draftStatus; textFormat: Text.PlainText; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                                ScrollView {
                                    visible: service.draftConflict
                                    Layout.fillWidth: true; Layout.preferredHeight: 70
                                    TextArea { text: service.draftConflictText || "(Saved draft is empty)"; readOnly: true; selectByMouse: true; wrapMode: TextArea.Wrap; color: view.ink; padding: 10; Accessible.name: "Saved draft from another client"; background: Rectangle { color: view.control; radius: 6; border.color: view.line } }
                                }
                                Action { visible: service.draftRecovered; text: "I checked — continue with this draft"; onClicked: service.reviewDraft() }
                                Action { visible: service.draftError; text: "Retry draft recovery"; onClicked: service.retryDraft() }
                        }
                    }
                    RowLayout {
                        visible: service.draftConflict
                        Action { objectName: "keepLocalDraft"; text: "Keep my text"; onClicked: service.resolveDraft(true) }
                        Action { objectName: "useSavedDraft"; text: "Use saved text"; onClicked: service.resolveDraft(false) }
                    }
                    ScrollView {
                        Layout.fillWidth: true; Layout.preferredHeight: view.narrow ? 56 : 76
                        TextArea {
                            id: composer
                            objectName: "composer"
                            placeholderText: service.hostedConnected ? "Message " + view.activeTitle + "…" : "Keep writing while offline…"
                            Accessible.name: "Message"
                            color: view.ink; placeholderTextColor: view.muted; selectionColor: colors.accent; selectedTextColor: colors.primaryInk
                            wrapMode: TextArea.Wrap; selectByMouse: true
                            font.pixelSize: colors.textBody; padding: 0
                            background: Item {}
                            onTextChanged: service.draft(text)
                            Keys.onPressed: function(event) {
                                if ((event.key === Qt.Key_Return || event.key === Qt.Key_Enter) && !(event.modifiers & Qt.ShiftModifier)) { if (sendButton.enabled) service.send(); event.accepted = true }
                            }
                        }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Enter to send · Shift+Enter for a new line"; color: view.muted; font.pixelSize: colors.textCaption; Layout.fillWidth: true; wrapMode: Text.WordWrap }
                        Text { visible: State.utf8Length(composer.text) > 3000; text: State.utf8Length(composer.text) + "/4096"; color: State.utf8Length(composer.text) > 4096 ? view.warning : view.muted; font.pixelSize: 10 }
                        Action { id: sendButton; objectName: "sendButton"; primary: true; text: view.activeBusy ? "Sending…" : "Send"; enabled: service.ready && !!service.hostedConnected && service.draftCanSend && !!view.active && !view.activeBusy && !view.draftNeedsReview && composer.text.trim().length > 0 && State.utf8Length(composer.text) <= 4096; onClicked: service.send() }
                    }
                }
            }
        }
    }
    component Sheet : AppDialog { theme: colors }
    Sheet {
        id: dm
        Connections { target: service; function onActionFinished(method) { if (method === "hosted-open-dm") { dm.close(); view.showChats = false; composer.forceActiveFocus() } } }
        title: "New direct message"
        onOpened: { service.actionError = ""; peer.forceActiveFocus() }
        onClosed: { peer.clear(); service.actionError = "" }
        contentItem: ColumnLayout {
            spacing: 16
            Text { text: "Enter a handle to start a direct conversation on your server."; color: view.muted; Layout.fillWidth: true; wrapMode: Text.WordWrap }
            Text { text: "Their handle"; color: view.ink; font.pixelSize: 13 }
            Field { id: peer; objectName: "peerKey"; placeholderText: "@handle"; Accessible.name: "Server handle"; maximumLength: 33; Layout.fillWidth: true; onAccepted: if (!service.actionBusy && service.hostedConnected && service.newDm(text)) { dm.close(); view.showChats = false; composer.forceActiveFocus() } }

            Text { text: service.actionError; textFormat: Text.PlainText; visible: text.length > 0; color: view.warning; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            RowLayout { Layout.alignment: Qt.AlignRight; Action { text: "Cancel"; onClicked: dm.close() } Action { text: service.actionBusy ? "Opening…" : "Open conversation"; primary: true; enabled: !!service.hostedConnected && !service.actionBusy && /^@?[a-z][a-z0-9_]{2,31}$/.test(peer.text.trim()); onClicked: if (service.newDm(peer.text)) { dm.close(); view.showChats = false; composer.forceActiveFocus() } } }
        }
    }
    Sheet {
        id: identity
        footer: Item { implicitHeight: 64; Action { anchors.right: parent.right; anchors.rightMargin: 24; text: "Done"; onClicked: identity.close() } }
        title: "My identity & connection"
        contentItem: ScrollView {
            id: identityScroll
            implicitHeight: Math.min(identityColumn.implicitHeight, view.height - 140)
            contentWidth: availableWidth
            ColumnLayout {
            id: identityColumn; width: identityScroll.availableWidth
            spacing: 16
            Text { text: view.connectionLabel; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Text { objectName: "hostedTrust"; visible: !!service.hosted && service.hosted.state !== "unconfigured" && service.hosted.state !== "disabled"; text: ((service.hosted || {}).url || "") + "\nThe operator can read messages on this server."; textFormat: Text.PlainText; color: view.muted; wrapMode: Text.WrapAnywhere; Layout.fillWidth: true }
            Field { id: hostedHandle; visible: !!service.hostedConnected && !(service.hosted || {}).handle; placeholderText: "Choose a hosted handle"; Layout.fillWidth: true; maximumLength: 32 }
            Action { text: "Claim hosted handle"; visible: !!service.hostedConnected && !(service.hosted || {}).handle; enabled: !service.actionBusy && hostedHandle.text.trim().length > 0; onClicked: service.request("hosted-claim-handle", {handle:hostedHandle.text.trim().replace(/^@/, "")}) }
            Text { text: service.actionError; visible: text.length > 0; color: view.warning; textFormat: Text.PlainText; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Text { text: "Your handle"; color: view.ink; font.pixelSize: 13 }
            TextArea { id: myLink; text: service.hosted.handle ? "@" + service.hosted.handle : "Choose a handle above"; textFormat: TextEdit.PlainText; readOnly: true; selectByMouse: true; color: view.ink; wrapMode: TextEdit.WrapAnywhere; padding: 10; Layout.fillWidth: true; Accessible.name: "My server handle"; background: Rectangle { color: view.control; radius: 6; border.color: view.line } }
            Action { text: "Copy handle"; enabled: !!service.hosted.handle; onClicked: { myLink.selectAll(); myLink.copy(); myLink.deselect() } }
            Text { text: "Share this handle with people on your server so they can message you."; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }

            }
        }
    }
    Sheet {
        id: admin; title: "Workspaces"
        footer: Item { implicitHeight: 64; Action { objectName: "closeWorkspaces"; anchors.right: parent.right; anchors.rightMargin: 24; text: "Done"; onClicked: admin.close() } }
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
            Text { text: "Bring your team together with shared channels."; color: view.muted; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Text { text: "Create a workspace"; color: view.ink; font.pixelSize: 15; font.weight: Font.DemiBold }
            Text { text: "Workspace name"; color: view.muted; font.pixelSize: 13 }
            RowLayout { Layout.fillWidth: true; spacing: 8
            Field { id: workspaceName; objectName: "workspaceName"; placeholderText: "New workspace name"; maximumLength: 64; Layout.fillWidth: true }
            Action { text: "Create workspace"; primary: true; enabled: !!service.hostedConnected && !service.actionBusy && workspaceName.text.trim().length > 0; onClicked: service.administer("hosted-create-workspace", "", workspaceName.text) }
            }
            Rectangle { Layout.fillWidth: true; Layout.topMargin: 8; Layout.bottomMargin: 8; height: 1; color: view.line }
            Text { text: "Manage a workspace"; color: view.ink; font.pixelSize: 15; font.weight: Font.DemiBold }
            Text { text: owned.count ? "Workspace you own" : "Create a workspace to add channels and invite people."; color: view.muted; font.pixelSize: 13; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            AppComboBox { visible: count > 0; theme: colors; id: owned; objectName: "ownedWorkspace"; Layout.fillWidth: true; model: (service.workspaces || []).filter(function(w) { return w.role === "owner" }); textRole: "name"; valueRole: "workspace_id"; Accessible.name: "Workspace you own" }
            Text { visible: owned.count > 0; text: "Channel name"; color: view.muted; font.pixelSize: 13 }
            RowLayout { Layout.fillWidth: true; spacing: 8; visible: owned.count > 0
            Field { visible: owned.count > 0; id: channelName; placeholderText: "New channel name"; maximumLength: 64; Layout.fillWidth: true }
            Action { text: "Create channel"; visible: owned.count > 0; enabled: !!service.hostedConnected && !service.actionBusy && owned.count > 0 && channelName.text.trim().length > 0; onClicked: service.administer("hosted-create-channel", owned.currentValue, channelName.text) }
            }
            Text { visible: owned.count > 0; text: "Add a person by handle"; color: view.muted; font.pixelSize: 13 }
            RowLayout { Layout.fillWidth: true; spacing: 8; visible: owned.count > 0
            Field { visible: owned.count > 0; id: memberHandle; placeholderText: "@handle"; maximumLength: 33; Layout.fillWidth: true }
            Action { text: "Add member"; visible: owned.count > 0; enabled: !!service.hostedConnected && !service.actionBusy && owned.count > 0 && memberHandle.text.trim().length > 0; onClicked: service.administer("hosted-add-member", owned.currentValue, memberHandle.text) }
            }
            Text { id: adminResult; visible: text.length > 0; color: view.accent; textFormat: Text.PlainText; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            Text { text: service.actionBusy ? "Working…" : service.actionError; visible: text.length > 0; color: view.warning; textFormat: Text.PlainText; wrapMode: Text.WordWrap; Layout.fillWidth: true }
            }
        }
    }
    ServerSetup { id: serverSetup; service: view.service }
    Shortcut { sequence: "Ctrl+N"; onActivated: view.needsSetup ? serverSetup.open() : dm.open() }
    Shortcut { sequence: "Ctrl+K"; onActivated: { view.showChats = true; filter.forceActiveFocus() } }
}
