// Deterministic test fixture. Never used by the production launcher.
import QtQuick
import QtQuick.Controls
import ".." as Desktop
import "../ChatState.js" as State
import "../Contact.js" as Contact
import "../Drafts.js" as Drafts

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
        property string draftStatus: "Session draft only — test fixture."
        property bool draftCanSend: true
        property bool draftConflict: false
        property string draftConflictText: ""
        property bool draftRecovered: false
        property bool draftError: false
        function resolveDraft(keepMine) { Drafts.resolve(State.current(state), keepMine); draftConflict = false; revision++ }
        function conflictFixture() {
            state.status.drafts_version = 1
            var c = State.current(state)
            Drafts.edit(c, "my unsaved text")
            Drafts.meta(c).conflict = { text: "their saved text", revision: 2 }
            draftConflict = true; draftConflictText = "their saved text"
            draftStatus = Drafts.label(state, c); revision++
        }
        function reviewDraft() { draftRecovered = false }
        function retryDraft() {}
        function pumpDrafts() {}
        function savedFixture() {
            state.status.drafts_version = 1
            var c = State.current(state)
            c.draft = "saved"
            var d = Drafts.meta(c)
            d.loaded = true; d.dirty = false; d.baseline = "saved"
            revision++
        }
        function dirtyFixture() { savedFixture(); Drafts.edit(State.current(state), "waiting to save"); revision++ }
        function pendingFixture() { State.current(state).busy = true; revision++ }
        function clearFixture() { state.chats.forEach(function(c) { c.draft = ""; c.busy = false; c.uncertain = false; c.savedDraft = undefined }); revision++ }
        property var rooms: []
        property bool actionBusy: false
        property string actionError: ""
        signal actionFinished(string method)
        function select(id) { State.select(state, id); revision++ }
        function draft(text) { var c = State.current(state); if (c && c.draft !== text) { Drafts.edit(c, text); revision++ } }
        function reviewedUnknown() { var c = State.current(state); c.uncertain = false; c.error = ""; revision++ }
        function request(method) {}
        function joinRoom(relay, group, code) {}
        function newDm(key) { var contact = Contact.preview(key); if (!contact.key) { actionError = contact.error; return false }; var opened = State.select(state, "dm:" + contact.key); revision++; return opened }
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
    Desktop.CloseGuard { service: mock }
}
