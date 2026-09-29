import QtQuick
import Quickshell
import Quickshell.Io
import "ChatState.js" as State
import "Contact.js" as Contact
import "Drafts.js" as Drafts

Item {
    id: service
    property var state: State.create()
    property int revision: 0
    readonly property bool ready: { revision; return state.ready }
    readonly property string notice: { revision; return state.notice }
    readonly property var chats: { revision; return state.chats.slice() }
    readonly property var activeChat: { revision; return State.current(state) }
    readonly property string publicKey: { revision; return state.status.nostr_public_key || "" }
    property bool focused: true
    property var rooms: []
    property var theme: ({})
    property string actionError: ""
    property bool actionBusy: false
    property var actions: ({})
    property int retryDelay: 1000
    property string socketPath: Quickshell.env("OMACHAT_SOCKET") || ((Quickshell.env("XDG_RUNTIME_DIR") || "") + "/omachat/omachat.sock")
    signal actionFinished(string method)
    property alias setup: relaySetup
    function settingsEdited(dirty) { state.settingsDirty = dirty; revision++ }
    SetupService {
        id: relaySetup
        onBusyChanged: { service.state.configBusy = busy; service.revision++ }
    }

    function select(id) { State.select(state, id); revision++ }
    readonly property string draftStatus: { revision; return Drafts.label(state, State.current(state)) }
    readonly property bool draftCanSend: { revision; return Drafts.canSend(state, State.current(state)) }
    readonly property bool draftConflict: { revision; var c = State.current(state); return !!c && !!Drafts.meta(c).conflict }
    readonly property string draftConflictText: { revision; var c = State.current(state); return c && Drafts.meta(c).conflict ? Drafts.meta(c).conflict.text : "" }
    readonly property bool draftRecovered: { revision; var c = State.current(state); return !!c && Drafts.meta(c).recovered }
    readonly property bool draftError: { revision; var c = State.current(state); return !!c && !!Drafts.meta(c).error }
    function draft(text) { var c = State.current(state); if (c && c.draft !== text) { Drafts.edit(c, text); revision++ } }
    function resolveDraft(keepMine) { var c = State.current(state); if (c) Drafts.resolve(c, keepMine); revision++ }
    function reviewDraft() { var c = State.current(state); if (c) Drafts.meta(c).recovered = false; revision++ }
    function retryDraft() { var c = State.current(state); if (c) { var d = Drafts.meta(c); d.loaded = false; d.error = "" }; revision++ }
    function pumpDrafts() {
        var before = Drafts.label(state, State.current(state))
        var request = Drafts.next(state)
        if (request) helper.write(JSON.stringify(request) + "\n")
        if (request || before !== Drafts.label(state, State.current(state))) revision++
    }
    function reviewedUnknown() { var c = State.current(state); if (c) { c.uncertain = false; c.error = ""; revision++ } }
    function markViewed() { var c = State.current(state); if (c && focused && c.unread) { c.unread = 0; revision++ } }
    onFocusedChanged: markViewed()
    function send() {
        if (!draftCanSend) return
        var request = State.beginSend(state)
        if (request) helper.write(JSON.stringify(request) + "\n")
        revision++
    }
    function newDm(key) {
        var contact = Contact.preview(key)
        if (!contact.key) { actionError = contact.error || "Paste a contact link or public key."; return false }
        if (!State.select(state, "dm:" + contact.key)) { actionError = state.notice; revision++; return false }
        actionError = ""; revision++; return true
    }
    function request(method, params) {
        if (!ready || actionBusy) return
        var id = "ui-" + (++state.serial)
        actions[id] = method; actionBusy = true; actionError = ""
        var value = { id: id, method: method }
        if (params !== undefined) value.params = params
        helper.write(JSON.stringify(value) + "\n")
    }
    function joinRoom(relay, group, code) {
        if (!relay || !group.trim()) { actionError = "Choose a configured relay and enter the room ID."; return }
        var params = { relay: relay, group_id: group.trim() }
        if (code.trim()) params.invite_code = code.trim()
        request("join-room", params)
    }
    function updateRooms(value) {
        rooms = value.relays || []
        rooms.forEach(function(relay) { (relay.rooms || []).forEach(function(room) {
            var c = State.ensure(state, room.conversation)
            if (c && room.name) c.title = room.name
        }) })
    }
    function receive(value) {
        if (value.kind === "theme") theme = value.data
        else if (value.kind === "snapshot") { State.snapshot(state, value.data); Drafts.reset(state); retryDelay = 1000 }
        else if (value.kind === "event") State.event(state, value.data, focused)
        else if (value.kind === "rooms") updateRooms(value.data)
        else if (value.kind === "disconnected") State.disconnected(state, value.error)
        else if (value.kind === "response" && Drafts.response(state, value, State.ensure)) {}
        else if (value.kind === "response" && state.pending[value.id]) {
            var sent = state.pending[value.id]
            State.response(state, value)
            var sentChat = State.ensure(state, sent.conversation)
            if (sentChat && value.ok) Drafts.meta(sentChat).dirty = true
        }
        else if (value.kind === "response") {
            var method = actions[value.id]; delete actions[value.id]; actionBusy = false
            if (!value.ok) actionError = value.error
            else {
                if (method === "list-rooms") updateRooms(value.data)
                if (method === "join-room") {
                    if (value.data && value.data.conversation) {
                        State.select(state, value.data.conversation)
                        var c = State.current(state)
                        if (c && value.data.name) c.title = value.data.name
                    }
                    state.notice = "Join requested; room admission is controlled by the relay."
                    request("list-rooms")
                }
                actionFinished(method)
            }
        }
        revision++
    }
    Timer { interval: 600; repeat: true; running: service.ready; onTriggered: service.pumpDrafts() }
    Process {
        id: helper
        command: ["/usr/bin/python3", Quickshell.shellPath("bridge.py"), "--socket", service.socketPath]
        stdinEnabled: true
        running: true
        stdout: SplitParser {
            onRead: function(line) {
                try { service.receive(JSON.parse(line)) }
                catch (_) { State.disconnected(service.state, "Desktop adapter returned an invalid frame."); service.revision++; helper.running = false }
            }
        }
        onRunningChanged: {
            if (!running) {
                State.disconnected(service.state, service.ready ? "Disconnected; reconnecting…" : service.state.notice)
                service.actions = ({}); service.actionBusy = false; service.revision++
                retry.restart()
            }
        }
    }
    Timer {
        id: retry
        interval: service.retryDelay
        onTriggered: {
            service.retryDelay = Math.min(30000, service.retryDelay * 2)
            helper.running = true
        }
    }
}
