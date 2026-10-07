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
    readonly property var hosted: { revision; return state.status.hosted || {} }
    readonly property bool hostedConnected: ready && hosted.state === "connected"
    readonly property var workspaces: { revision; return state.workspaces || [] }
    property var hostedPending: ({})
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

    function select(id) { State.select(state, id); loadHistory(false); revision++ }
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
    function markViewed() {
        var c = State.current(state); if (!c || !focused) return
        if (c.id.indexOf("hosted:") === 0) {
            if (!c.historyLoaded || !hostedConnected) return
            var sequence = c.messages.reduce(function(n,m) { return Math.max(n, m.sequence || 0) }, 0)
            if (sequence > (c.readSequence || 0) && Date.now() >= (c.readRetryAt || 0)) { c.readRetryAt = Date.now() + 5000; hostedRequest("hosted-mark-read", {conversation:c.id, sequence:sequence}, "read:" + c.id) }
        } else if (c.unread) { c.unread = 0; revision++ }
    }
    function hostedRequest(method, params, key) {
        if (!state.ready || !state.status.hosted || state.status.hosted.state !== "connected") return
        if (Object.keys(hostedPending).some(function(id) { return hostedPending[id].key === key })) return
        var id = "ui-" + (++state.serial)
        hostedPending[id] = {method:method, params:params, key:key}
        helper.write(JSON.stringify({id:id, method:method, params:params}) + "\n")
    }
    function refreshHosted() { hostedRequest("hosted-conversations", undefined, "list") }
    function loadHistory(older) {
        var c = State.current(state)
        if (!c || c.id.indexOf("hosted:") !== 0) return
        var params = {conversation:c.id, limit:50}
        if (older && c.messages.length) params.before_sequence = c.messages[0].sequence
        hostedRequest("hosted-history", params, "history:" + c.id)
    }
    function ownedWorkspace(id) { return workspaces.some(function(w) { return w.workspace_id === id && w.role === "owner" }) }
    function administer(method, workspace, value) {
        if (!hostedConnected) return
        if (method !== "hosted-create-workspace" && !ownedWorkspace(workspace)) { actionError = "Only workspace owners can do this."; return }
        var params = method === "hosted-add-member" ? {workspace_id:workspace, handle:value.trim().replace(/^@/, "")} : {name:value.trim()}
        if (method === "hosted-create-channel") params.workspace_id = workspace
        request(method, params)
    }
    onFocusedChanged: markViewed()
    function send() {
        if (!draftCanSend) return
        var request = State.beginSend(state)
        if (request) helper.write(JSON.stringify(request) + "\n")
        revision++
    }
    function newDm(key) {
        if (key.trim().charAt(0) === "@" && hostedConnected) {
            request("hosted-open-dm", {handle:key.trim().slice(1)}); return false
        }
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
        else if (value.kind === "snapshot") { State.snapshot(state, value.data); Drafts.reset(state); hostedPending = ({}); state.chats.forEach(function(c) { c.historyLoaded = false }); retryDelay = 1000; loadHistory(false) }
        else if (value.kind === "event") {
            var wasConnected = state.status.hosted && state.status.hosted.state === "connected"
            State.event(state, value.data, focused)
            if (value.data.topic === "status" && !wasConnected && state.status.hosted && state.status.hosted.state === "connected") { refreshHosted(); loadHistory(false) }
            if (value.data.topic === "conversations" && value.data.payload.transport === "hosted") refreshHosted()
            markViewed()
        }
        else if (value.kind === "hosted-list") { if (value.ok) { State.hostedList(state, value.data); loadHistory(false) } else state.notice = value.error }
        else if (value.kind === "response" && hostedPending[value.id]) {
            var job = hostedPending[value.id]; delete hostedPending[value.id]
            if (!value.ok) state.notice = value.error || "Hosted request failed; retry when connected."
            else if (job.method === "hosted-conversations") { State.hostedList(state, value.data); if (!State.current(state) || !State.current(state).historyLoaded) loadHistory(false) }
            else if (job.method === "hosted-history") {
                if (job.params.before_sequence && value.data.messages && value.data.messages.length) { var pageChat = State.ensure(state, job.params.conversation); if (pageChat) pageChat.messages = [] }
                State.hostedHistory(state, value.data); markViewed()
            }
            else if (job.method === "hosted-mark-read") State.hostedReceipt(state, value.data)
        }
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
                if (method && method.indexOf("hosted-") === 0) {
                    if (value.data && value.data.conversation) { State.hostedConversation(state, value.data); select(value.data.conversation) }
                    refreshHosted()
                }
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
    Timer { interval: 600; repeat: true; running: service.ready; onTriggered: { service.pumpDrafts(); service.markViewed() } }
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
                service.actions = ({}); service.hostedPending = ({}); service.actionBusy = false; service.revision++
                retry.restart()
            }
        }
    }
    Timer {
        id: retry
        interval: service.retryDelay
        onTriggered: {
            service.retryDelay = Math.min(10000, service.retryDelay * 2)
            helper.running = true
        }
    }
}
