// Pure presentation state; daemon remains authoritative for delivery/history.
function create() {
    return { chats: [], active: "", ready: false, status: {}, notice: "Connecting to OmaChat…", serial: 0, pending: {} };
}
function shortKey(key) { return key.length > 20 ? key.slice(0, 10) + "…" + key.slice(-6) : key; }
function ensure(s, id) {
    var chat = s.chats.find(function(c) { return c.id === id; });
    if (chat) return chat;
    if (typeof id !== "string" || id.length > 512 || s.chats.length >= 128) return null;
    chat = { id: id, title: id.indexOf("dm:") === 0 ? shortKey(id.slice(3)) : id,
             messages: [], draft: "", unread: 0, busy: false, uncertain: false, error: "" };
    s.chats.push(chat);
    return chat;
}
function select(s, id) {
    var chat = ensure(s, id);
    if (!chat) { s.notice = "This session has reached its 128-conversation limit."; return; }
    s.active = id; chat.unread = 0;
}
function current(s) { return s.chats.find(function(c) { return c.id === s.active; }) || null; }
function applyMessage(s, p, historical, focused) {
    if (!p || typeof p.id !== "string") return;
    var chat = p.conversation ? ensure(s, p.conversation) : s.chats.find(function(c) { return c.messages.some(function(m) { return m.id === p.id; }); });
    if (!chat) return;
    var old = chat.messages.find(function(m) { return m.id === p.id; });
    if (p.deleted) { chat.messages = chat.messages.filter(function(m) { return m.id !== p.id; }); return; }
    if (old) { if (p.delivery) old.delivery = p.delivery; return; }
    if (typeof p.text !== "string") return;
    var outgoing = p.outgoing === true || (p.delivery && p.delivery !== "received");
    chat.messages.push({ id: p.id, text: p.text, sender: p.sender || "Peer", outgoing: !!outgoing, delivery: p.delivery || "received" });
    if (chat.messages.length > 128) chat.messages.shift();
    if (!historical && !outgoing && (s.active !== chat.id || !focused)) chat.unread++;
}
function snapshot(s, value) {
    // Replace the recent view; preserve session drafts, selection and unknown sends.
    var changedIdentity = s.status.nostr_public_key && value.status && s.status.nostr_public_key !== value.status.nostr_public_key;
    if (changedIdentity) { s.chats = []; s.active = ""; s.pending = {}; }
    s.chats.forEach(function(c) { c.messages = []; });
    s.status = value.status || {};
    (value.messages || []).forEach(function(p) { applyMessage(s, p, true, true); });
    (s.status.joined_geohashes || []).forEach(function(g) { ensure(s, "#" + g); });
    s.ready = true; s.notice = changedIdentity ? "Daemon identity changed; previous conversations and drafts were cleared." : "Connected to local daemon";
    if (!s.active && s.chats.length) select(s, s.chats[0].id);
}
function event(s, value, focused) {
    if (value.topic === "messages" || value.topic === "delivery") applyMessage(s, value.payload, false, focused);
    else if (value.topic === "status") s.status = value.payload;
    else if (value.topic === "conversations" && value.payload.conversation) {
        var c = ensure(s, value.payload.conversation);
        if (c && value.payload.name) c.title = value.payload.name;
    }
}
function utf8Length(text) {
    // encodeURIComponent rejects unpaired surrogates; reject rather than truncate.
    try { return unescape(encodeURIComponent(text)).length; } catch (_) { return Infinity; }
}
function beginSend(s) {
    var c = current(s);
    if (!s.ready || !c || c.busy || c.uncertain || !c.draft.trim()) return null;
    if (c.id.indexOf("dm:") === 0 && !(s.status.dm_relay_count > 0)) {
        c.error = "Configure a NIP-17 DM relay and restart the daemon before sending. See desktop/README.md."; return null;
    }
    if (utf8Length(c.draft) > 4096) { c.error = "Keep this message within 4,096 UTF-8 bytes."; return null; }
    var id = "ui-" + (++s.serial);
    s.pending[id] = { conversation: c.id, text: c.draft };
    c.busy = true; c.error = "";
    return { id: id, method: "send", params: { conversation: c.id, text: c.draft } };
}
function response(s, value) {
    var sent = s.pending[value.id];
    if (!sent) return false;
    delete s.pending[value.id];
    var c = ensure(s, sent.conversation);
    if (!c) return true;
    c.busy = false;
    if (!value.ok) { c.error = value.error || "Message rejected; draft kept."; return true; }
    // A reply belongs to the chat/text at submission, never whichever is selected now.
    if (c.draft === sent.text) c.draft = "";
    var data = value.data || {};
    if (data.id) applyMessage(s, { id: data.id, conversation: c.id, text: sent.text, sender: "You", outgoing: true, delivery: data.delivery || "unknown" }, true, true);
    c.error = "";
    return true;
}
function disconnected(s, reason) {
    s.ready = false; s.notice = reason || "Disconnected; reconnecting…";
    Object.keys(s.pending).forEach(function(id) {
        var c = ensure(s, s.pending[id].conversation);
        if (c) { c.busy = false; c.uncertain = true; c.error = "Delivery is unknown. Check the conversation before sending again."; }
    });
    s.pending = {};
}
function deliveryLabel(value) {
    return { queued: "Queued by daemon", stored: "Stored by relay", failed: "Failed", created: "Created locally", received: "", unknown: "Accepted · delivery unknown" }[value] || "Delivery unknown";
}
function dmKey(value) {
    var key = value.trim().replace(/^dm:/, "");
    return /^[0-9a-fA-F]{64}$/.test(key) ? key.toLowerCase() : "";
}
