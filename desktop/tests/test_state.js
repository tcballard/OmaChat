const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const context = vm.createContext({});
vm.runInContext(fs.readFileSync(__dirname + "/../ChatState.js", "utf8"), context);
const state = context.create();
context.snapshot(state, {
    identity: {present: true, npub: "npub1example", pubkey: "aa"},
    relays: ["wss://relay.example"],
    contacts: [{pubkey: "bb", display: "ada", npub: "npub1ada"}],
    messages: [{id: "1", conversation: "dm:bb", peer: "bb", text: "hi", outgoing: false}],
    status: {hosted: {state: "disabled"}},
});
assert.equal(state.npub, "npub1example");
assert.equal(context.currentMessages(state).length, 1);
context.event(state, {topic: "messages", payload: {id: "2", conversation: "dm:bb", peer: "bb", text: "yo", outgoing: true}});
assert.equal(context.currentMessages(state).length, 2);
context.event(state, {topic: "messages", payload: {id: "2", conversation: "dm:bb", peer: "bb", text: "yo", outgoing: true, delivery: "stored"}});
assert.equal(context.currentMessages(state).length, 2);
console.log("PASS: snapshot, selection, and message dedup");

context.setDraft(state, "keep me");
context.beginSend(state, "ui-1", "keep me");
assert.equal(context.sending(state), true);
context.finishSend(state, {id: "ui-unrelated", ok: true});
assert.equal(context.draft(state), "keep me");
context.finishSend(state, {id: "ui-1", ok: false});
assert.equal(context.draft(state), "keep me");
assert.equal(context.sending(state), false);
context.beginSend(state, "ui-2", "keep me");
context.setDraft(state, "newer typing");
context.finishSend(state, {id: "ui-2", ok: true});
assert.equal(context.draft(state), "newer typing");
context.beginSend(state, "ui-3", "newer typing");
context.select(state, "cc");
context.setDraft(state, "other conversation");
context.finishSend(state, {id: "ui-3", ok: true});
assert.equal(context.draft(state), "other conversation");
context.select(state, "bb");
assert.equal(context.draft(state), "");
context.setDraft(state, "uncertain");
context.beginSend(state, "ui-4", "uncertain");
assert.equal(context.disconnect(state), true);
assert.equal(context.draft(state), "uncertain");
assert.equal(context.sending(state), false);
assert.equal(state.ready, false);
console.log("PASS: failed and uncertain sends preserve per-contact drafts; correlated success clears only the sent text");
