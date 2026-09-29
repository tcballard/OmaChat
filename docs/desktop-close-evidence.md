# Close guard development evidence

The production CloseGuard connects to the Qt window attached to its Item; it is
shared by the Quickshell shell and offscreen Qt fixture. It blocks normal close
while any conversation has unsaved text, a pending send/save, conflicts, or an
unknown send outcome. Save-and-close waits for acknowledged state with a ten
second limit; it never auto-discards or resends messages. Explicit close-anyway
loses memory-only edits and does not undo queued sends or remove sealed drafts.

Portable checks: Qt window close acceptance/rejection, keep-editing, explicit
discard, saved-draft close, and acknowledgement-before-close. JavaScript checks
cover background chats and state combinations. These do not prove compositor
shortcut handling on a live Omarchy/Quickshell installation. Forced termination,
resource loss and hot reload are not cancellable through this guard.

Source API checked against Quickshell QsWindow documentation v0.3.1 and its
upstream proxywindow.cpp: normal closing is owned by the backing QQuickWindow;
QsWindow.closed is emitted after visibility changes. No invented QsWindow
onClosing signal is used. Live XPS acceptance remains a release gate.
