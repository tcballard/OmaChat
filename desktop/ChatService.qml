import QtQuick
import Quickshell
import Quickshell.Io
import "ChatState.js" as State
import "Contact.js" as Contact

Item {
    id: service
    property var state: State.create()
    property int revision: 0
    readonly property bool ready: { revision; return state.ready }
    readonly property string npub: { revision; return state.npub }
    readonly property var contacts: { revision; return state.contacts }
    readonly property var relays: { revision; return state.relays }
    readonly property var messages: { revision; return State.currentMessages(state) }
    readonly property string selectedKey: { revision; return state.selected || "" }
    readonly property string notice: { revision; return state.notice }
    readonly property var hosted: { revision; return state.hosted || {} }
    readonly property string draft: { revision; return State.draft(state) }
    readonly property bool sending: { revision; return State.sending(state) }
    property string actionError: ""
    property string socketPath: Quickshell.env("OMACHAT_SOCKET") || ((Quickshell.env("XDG_RUNTIME_DIR") || "") + "/omachat/omachat.sock")

    function bump() { revision++ }
    function request(method, params) {
        if (!state.ready) return ""
        var id = "ui-" + (++state.serial)
        var value = {id: id, method: method}
        if (params !== undefined) value.params = params
        helper.write(JSON.stringify(value) + "\n")
        return id
    }
    function copyNpub() {
        if (!state.npub) return
        clipboard.text = state.npub
        clipboard.selectAll()
        clipboard.copy()
        state.notice = "npub copied"
        bump()
    }
    function addContact(raw) {
        var value = raw.trim()
        if (!value) return
        if (value.indexOf("@") > 0 && value.indexOf("npub") !== 0) {
            request("contacts-add", {peer: value})
            return
        }
        var parsed = Contact.preview(value)
        if (!parsed.key) { actionError = parsed.error || "Use an npub or name@domain."; bump(); return }
        actionError = ""
        request("contacts-add", {peer: parsed.key})
    }
    function select(pubkey) { State.select(state, pubkey); bump() }
    function setDraft(text) { State.setDraft(state, text); bump() }
    function send(text) {
        if (!state.ready || !state.selected || !text.trim() || State.sending(state)) return
        var id = request("send", {peer: state.selected, text: text})
        State.beginSend(state, id, text)
        actionError = ""
        bump()
    }
    function saveRelays(text) {
        var relays = text.split("\n").map(function(line) { return line.trim() }).filter(function(line) { return line.length > 0 })
        request("relays-set", {relays: relays})
    }
    function claim(handle) { request("hosted-claim-handle", {handle: handle.trim().replace(/^@/, "")}) }
    function bind() { request("hosted-bind-nostr") }
    function receive(value) {
        if (value.kind === "snapshot") State.snapshot(state, value.data)
        else if (value.kind === "event") State.event(state, value.data)
        else if (value.kind === "identity") {
            if (value.ok && value.data && value.data.npub) state.npub = value.data.npub
            else if (!value.ok) state.notice = value.error
        }
        else if (value.kind === "response") {
            State.finishSend(state, value)
            if (!value.ok) actionError = value.error || "Request failed"
            else {
                actionError = ""
                if (value.data && value.data.contact) {
                    state.contacts = state.contacts.filter(function(contact) { return contact.pubkey !== value.data.contact.pubkey })
                    state.contacts.push(value.data.contact)
                    state.selected = value.data.contact.pubkey
                }
                if (value.data && value.data.relays) state.relays = value.data.relays
                if (value.data && value.data.npub) state.npub = value.data.npub
                state.notice = ""
            }
        }
        else if (value.kind === "disconnected") {
            if (State.disconnect(state)) actionError = "Send outcome unknown. Check the conversation before sending again. Your draft is kept."
            state.notice = value.error || "Disconnected; reconnecting"
        }
        bump()
    }

    TextEdit { id: clipboard; visible: false }

    Process {
        id: helper
        command: ["/usr/bin/python3", Quickshell.shellPath("bridge.py"), "--socket", service.socketPath]
        stdinEnabled: true
        running: true
        stdout: SplitParser {
            onRead: function(line) {
                try { service.receive(JSON.parse(line)) }
                catch (error) { service.state.notice = "Desktop adapter returned an invalid frame."; service.revision++; helper.running = false }
            }
        }
        onRunningChanged: if (!running) {
            service.receive({kind: "disconnected", error: "Disconnected; reconnecting"})
            retry.restart()
        }
    }
    Timer {
        id: retry
        interval: 2000
        onTriggered: helper.running = true
    }
}
