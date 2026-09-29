// Deterministic test fixture. Never used by the production launcher.
import QtQuick
import QtQuick.Controls
import ".." as Desktop
import "../ChatState.js" as State

ApplicationWindow {
    id: window
    width: 1080; height: 760; visible: true
    title: "OmaChat — test fixture"
    property alias backend: mock
    QtObject {
        id: mock
        property var state: State.create()
        property int revision: 0
        property var theme: ({})
        readonly property bool ready: { revision; return state.ready }
        readonly property string notice: { revision; return state.notice }
        readonly property var chats: { revision; return state.chats.slice() }
        readonly property var activeChat: { revision; return State.current(state) }
        readonly property string publicKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        property var rooms: []
        property bool actionBusy: false
        property string actionError: ""
        signal actionFinished(string method)
        function select(id) { State.select(state, id); revision++ }
        function draft(text) { var c = State.current(state); if (c) c.draft = text }
        function reviewedUnknown() { var c = State.current(state); c.uncertain = false; c.error = ""; revision++ }
        function request(method) {}
        function joinRoom(relay, group, code) {}
        function newDm(key) { var k = State.dmKey(key); if (!k) { actionError = "Invalid public key"; return false }; var opened = State.select(state, "dm:" + k); revision++; return opened }
        function send() {
            var req = State.beginSend(state)
            if (req) State.response(state, { id: req.id, ok: true, data: { id: "sent-" + state.serial, delivery: "stored" } })
            revision++
        }
        function offline() { State.disconnected(state, "Daemon disconnected; reconnecting…"); revision++ }
        Component.onCompleted: {
            State.snapshot(state, { status: {dm_relay_count:1}, messages: [
                { id: "1", conversation: "dm:" + "b".repeat(64), sender: "Sam", text: "The desktop preview is ready. Can you try sending a message?", delivery: "received" },
                { id: "2", conversation: "dm:" + "b".repeat(64), sender: "You", text: "Yes. I want the essentials to feel effortless: open a chat, write, send, and know what happened.", outgoing: true, delivery: "stored" },
                { id: "3", conversation: "dm:" + "b".repeat(64), sender: "Sam", text: "Agreed. Let’s start there.", delivery: "received" }
            ] })
            State.current(state).title = "Sam"
            var room = State.ensure(state, "room:" + "c".repeat(64) + ":omachat"); room.title = "OmaChat development"
            revision++
        }
    }
    Desktop.ChatView { anchors.fill: parent; service: mock }
}
