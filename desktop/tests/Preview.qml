// Deterministic test fixture. Never used by the production launcher.
import QtQuick
import QtQuick.Controls
import ".." as Desktop
import "../ChatState.js" as State
import "../Drafts.js" as Drafts

ApplicationWindow {
    id: window
    width: 1080; height: 760; visible: true
    title: "OmaChat — test fixture"
    property alias backend: mock
    QtObject {
        id: setupMock
        property bool busy: false
        property string error: ""
        property string path: "/tmp/omachat-test-config.json"
        property string configRevision: "test"
        property var hosted: ({})
        property string backup: ""
        property bool restartRequired: false
        signal loaded()
        function read(path) { loaded() }
        function save(value) { hosted = value; restartRequired = true; loaded() }
    }
    QtObject {
        id: mock
        property var setup: setupMock
        function settingsEdited(dirty) { state.settingsDirty = dirty; revision++ }
        property var state: State.create()
        property int revision: 0
        property var theme: ({})
        property var hosted: ({state:"connected",handle:"alice"})
        property bool hostedConnected: true
        property var workspaces: []
        function refreshHosted() {}
        function loadHistory(older) {}
        function administer(method, workspace, value) {}
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
        function uncertainFixture() { var c = State.current(state); c.uncertain = true; c.error = "Delivery is unknown. Check the conversation before sending again."; revision++ }
        function clearFixture() { state.settingsDirty = false; state.configBusy = false; state.chats.forEach(function(c) { c.draft = ""; c.busy = false; c.uncertain = false; c.savedDraft = undefined }); revision++ }
        property bool actionBusy: false
        property string actionError: ""
        signal actionFinished(string method)
        function select(id) { State.select(state, id); revision++ }
        function draft(text) { var c = State.current(state); if (c && c.draft !== text) { Drafts.edit(c, text); revision++ } }
        function reviewedUnknown() { var c = State.current(state); c.uncertain = false; c.error = ""; revision++ }
        function request(method) {}
        function newDm(key) { if (!/^@?[a-z][a-z0-9_]{2,31}$/.test(key)) { actionError = "Invalid handle"; return false }; var opened = State.select(state, "hosted:" + key.replace(/^@/, "")); revision++; return opened }
        function send() {
            var req = State.beginSend(state)
            if (req) State.response(state, { id: req.id, ok: true, data: { id: "sent-" + state.serial, delivery: "stored" } })
            revision++
        }
        function offline() { State.disconnected(state, "Daemon disconnected; reconnecting…"); revision++ }
        Component.onCompleted: {
            State.snapshot(state, { status: {hosted:{state:"connected"}}, messages: [
                { id: "1", conversation: "hosted:" + "b".repeat(64), sender: "Sam", text: "The desktop preview is ready. Can you try sending a message?", delivery: "received" },
                { id: "2", conversation: "hosted:" + "b".repeat(64), sender: "You", text: "Yes. I want the essentials to feel effortless: open a chat, write, send, and know what happened.", outgoing: true, delivery: "stored" },
                { id: "3", conversation: "hosted:" + "b".repeat(64), sender: "Sam", text: "Agreed. Let’s start there.", delivery: "received" }
            ] })
            State.current(state).title = "Sam"
            var room = State.ensure(state, "hosted:channel"); room.title = "OmaChat development"
            revision++
        }
    }
    Desktop.ChatView { anchors.fill: parent; service: mock }
    Desktop.CloseGuard { service: mock }
}
