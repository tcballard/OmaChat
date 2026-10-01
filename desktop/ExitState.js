// Closing is safe only after all user-authored work is accounted for.
function inspect(s) {
    var unsaved = 0, pending = 0, conflicts = 0, unknown = 0;
    s.chats.forEach(function(c) {
        var d = c.savedDraft;
        if (c.busy || (d && d.pending && d.dirty)) pending++;
        if (c.uncertain) unknown++;
        if (d && d.conflict) conflicts++;
        if (s.status.drafts_version === 1) {
            if ((d && d.dirty) || (c.draft && (!d || !d.loaded))) unsaved++;
        } else if (c.draft) unsaved++;
    });
    if (s.settingsDirty) unsaved++;
    if (s.configBusy) pending++;
    return { safe: !(unsaved || pending || conflicts || unknown), unsaved: unsaved,
             pending: pending, conflicts: conflicts, unknown: unknown };
}
function describe(s) {
    var result = inspect(s), parts = [];
    if (s.settingsDirty) parts.push("Server settings have unapplied edits.");
    if (s.configBusy) parts.push("A configuration operation is still running.");
    if (result.unsaved) parts.push(result.unsaved + " conversation(s) have unsaved draft changes.");
    if (result.pending) parts.push("A save or send is still waiting for the daemon.");
    if (result.conflicts) parts.push("Resolve draft conflicts before saving and closing.");
    if (result.unknown) parts.push("A send has an unknown outcome. Check the conversation before resending.");
    parts.push("Closing anyway loses unsaved changes. Existing saved drafts remain; queued sends may still complete.");
    return parts.join("\n\n");
}
