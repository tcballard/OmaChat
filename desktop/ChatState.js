function create() {
    return {
        ready: false,
        notice: "",
        npub: "",
        pubkey: "",
        relays: [],
        contacts: [],
        messages: [],
        selected: "",
        hosted: {},
        serial: 0,
    };
}

function snapshot(state, data) {
    state.ready = true;
    state.notice = "";
    state.relays = data.relays || [];
    state.contacts = data.contacts || [];
    state.messages = data.messages || [];
    var identity = data.identity || {};
    state.npub = identity.npub || "";
    state.pubkey = identity.pubkey || "";
    state.hosted = (data.status && data.status.hosted) || {};
    if (!state.selected && state.contacts.length) state.selected = state.contacts[0].pubkey;
}

function event(state, data) {
    if (!data || !data.payload) return;
    if (data.topic === "messages") {
        var message = data.payload;
        var index = state.messages.findIndex(function(existing) { return existing.id === message.id; });
        if (index >= 0) state.messages[index] = message;
        else state.messages.push(message);
        if (state.messages.length > 128) state.messages.shift();
    } else if (data.topic === "conversations" && data.payload.conversation) {
        var pubkey = String(data.payload.conversation).replace(/^dm:/, "");
        if (!state.contacts.some(function(contact) { return contact.pubkey === pubkey; })) {
            state.contacts.push({pubkey: pubkey, display: data.payload.name || pubkey, npub: ""});
        }
    } else if (data.topic === "status") {
        state.hosted = data.payload.hosted || state.hosted;
        if (data.payload.nostr && data.payload.nostr.npub) state.npub = data.payload.nostr.npub;
    }
}

function currentMessages(state) {
    return state.messages.filter(function(message) {
        return message.peer === state.selected || message.conversation === "dm:" + state.selected;
    });
}

function select(state, pubkey) {
    state.selected = pubkey;
}
