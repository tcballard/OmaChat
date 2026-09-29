// Sealed persistence is owned by the daemon. This module holds only UI state.
function supported(s) { return s.status.drafts_version === 1; }
function meta(c) {
    if (!c.savedDraft) c.savedDraft = { loaded: false, revision: 0, baseline: "", dirty: false, pending: false, conflict: null, error: "", recovered: false };
    return c.savedDraft;
}
function reset(s) {
    s.draftRequests = {};
    s.draftListNeeded = true;
    s.chats.forEach(function(c) { var d = meta(c); d.loaded = false; d.pending = false; d.error = ""; });
}
function edit(c, text) {
    var d = meta(c);
    if (c.draft === text) return;
    c.draft = text; d.dirty = true; d.error = "";
}
function issue(s, method, c, params) {
    var id = "ui-" + (++s.serial);
    if (!s.draftRequests) s.draftRequests = {};
    s.draftRequests[id] = { method: method, chat: c, text: c ? c.draft : "" };
    if (c) meta(c).pending = true;
    var request = { id: id, method: method };
    if (params) request.params = params;
    return request;
}
function next(s) {
    if (!s.ready || !supported(s)) return null;
    if (s.draftListNeeded) { s.draftListNeeded = false; return issue(s, "list-drafts", null); }
    // A user can type and switch chats before the first read completes.
    // Recover dirty background chats too, otherwise they can never be saved.
    var active = s.chats.find(function(c) {
        var d = meta(c);
        return d.dirty && !d.loaded && !d.pending && !d.error;
    }) || s.chats.find(function(c) { return c.id === s.active; });
    if (active && !meta(active).loaded && !meta(active).pending && !meta(active).error)
        return issue(s, "get-draft", active, { conversation: active.id });
    var c = s.chats.find(function(c) {
        var d = meta(c);
        return d.loaded && d.dirty && !d.pending && !d.conflict && !d.error && !c.busy;
    });
    if (!c) return null;
    var d = meta(c);
    try {
        if (unescape(encodeURIComponent(c.draft)).length > 4096) throw Error();
    } catch (_) { d.error = "Draft exceeds 4,096 UTF-8 bytes; shorten it to save."; return null; }
    return issue(s, "save-draft", c, { conversation: c.id, text: c.draft, expected_revision: d.revision });
}
function response(s, value, ensure) {
    var request = (s.draftRequests || {})[value.id];
    if (!request) return false;
    delete s.draftRequests[value.id];
    if (request.method === "list-drafts") {
        if (!value.ok) { s.notice = "Saved drafts could not be listed: " + value.error; return true; }
        (value.data.drafts || []).forEach(function(item) { ensure(s, item.conversation); });
        if (!s.active && s.chats.length) s.active = s.chats[0].id;
        return true;
    }
    var c = request.chat, d = meta(c);
    d.pending = false;
    if (!value.ok) { d.error = value.error || "Draft was not saved."; return true; }
    var remote = value.data;
    if (!remote || remote.conversation !== c.id || typeof remote.text !== "string" || !Number.isSafeInteger(remote.revision)) {
        d.error = "Invalid saved draft response."; return true;
    }
    if (request.method === "save-draft" && remote.saved !== true) {
        d.conflict = remote; return true;
    }
    if (request.method === "get-draft") {
        d.loaded = true;
        if (d.dirty && remote.text !== c.draft && remote.text !== d.baseline) {
            d.conflict = remote; return true;
        }
        if (!d.dirty) {
            c.draft = remote.text;
            d.recovered = !!remote.text;
        }
    }
    d.baseline = remote.text; d.revision = remote.revision;
    d.dirty = c.draft !== remote.text;
    d.conflict = null; d.error = "";
    return true;
}
function resolve(c, keepMine) {
    var d = meta(c), remote = d.conflict;
    if (!remote) return;
    d.baseline = remote.text; d.revision = remote.revision; d.loaded = true;
    if (!keepMine) { c.draft = remote.text; d.recovered = !!remote.text; }
    d.dirty = c.draft !== remote.text; d.conflict = null; d.error = "";
}
function canSend(s, c) {
    if (!c || !supported(s)) return true;
    var d = meta(c);
    return d.loaded && !d.conflict && !d.recovered;
}
function label(s, c) {
    if (!c) return "";
    if (!supported(s)) return "Session draft only — daemon does not support saved drafts.";
    var d = meta(c);
    if (d.conflict) return "Another client changed this draft. Choose which version to keep.";
    if (d.error) return d.error;
    if (!s.ready) return "Offline — keep this window open to preserve unsaved changes.";
    if (!d.loaded) return "Loading saved draft…";
    if (d.recovered) return "Recovered draft — check the conversation before sending again.";
    if (d.pending || d.dirty) return "Saving draft — keep this window open…";
    return c.draft ? "Draft saved securely on this device." : "No saved draft.";
}
