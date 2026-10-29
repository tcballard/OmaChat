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
