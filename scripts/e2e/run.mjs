import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createInterface } from 'node:readline';
import { WebSocket } from 'ws';
import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { npubEncode, nsecEncode } from 'nostr-tools/nip19';
import { wrapEvent, unwrapEvent } from 'nostr-tools/nip17';
import { relay } from './relay.mjs';

const root = resolve(import.meta.dirname, '../..');
const bins = resolve(process.env.OMACHAT_BIN_DIR || join(root, 'target/debug'));
const scratch = await mkdtemp(join(tmpdir(), 'omachat-e2e-'));
const children = new Set();
const transcripts = [];
const secrets = [];
let transport;
let external;

function processFor(command, args) {
  const child = spawn(command, args, {
    cwd: root, stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, TERM: 'xterm-256color' },
  });
  child.output = '';
  child.errors = '';
  child.stdout.on('data', data => { child.output += data; });
  child.stderr.on('data', data => { child.errors += data; });
  child.on('error', error => { child.spawnError = error; });
  children.add(child);
  transcripts.push(child);
  return child;
}
async function until(description, predicate, milliseconds = 15000) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await delay(50);
  }
  throw new Error('Timed out: ' + description);
}
async function stop(child) {
  if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, 'exit');
  child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
  try { await exited; } finally { clearTimeout(timer); children.delete(child); }
}
async function finish(child, milliseconds = 35000) {
  const timer = setTimeout(() => child.kill('SIGKILL'), milliseconds);
  try { await once(child, 'close'); } finally { clearTimeout(timer); children.delete(child); }
}
async function ctl(user, args, expected = 0, privateOutput = false) {
  const child = processFor(join(bins, 'omachat-ctl'), ['--socket', user.socket, ...args]);
  await finish(child);
  assert.equal(child.exitCode, expected, args[0] + ' failed: ' + child.errors);
  const output = child.output;
  if (privateOutput) child.output = '';
  return expected === 0 ? JSON.parse(output) : child.errors;
}
async function startDaemon(user) {
  user.child = processFor(join(bins, 'omachatd'), [
    '--config', user.config, '--state', user.state, '--socket', user.socket, '--file-key',
  ]);
  await until(user.name + ' daemon ready', async () => {
    if (user.child.spawnError) throw user.child.spawnError;
    if (user.child.exitCode !== null) throw new Error(user.child.errors);
    try { return (await ctl(user, ['status', '--json'])).hosted.state === 'connected'; } catch { return false; }
  });
}
async function user(name, handleUrl, pin) {
  const directory = join(scratch, name);
  await mkdir(directory, { mode: 0o700 });
  const value = {
    name, socket: join(directory, 'ipc.sock'),
    state: join(directory, 'state'), config: join(directory, 'config.json'),
  };
  await writeFile(value.config, JSON.stringify({
    hosted: { url: handleUrl, pinned_server_public_key: pin }, dm_relays: [transport.url],
  }));
  await startDaemon(value);
  return value;
}
async function bridge(user) {
  const child = processFor('python3', [join(root, 'desktop/bridge.py'), '--socket', user.socket]);
  const frames = [];
  createInterface({ input: child.stdout }).on('line', line => frames.push(JSON.parse(line)));
  await until('desktop adapter identity', () => frames.some(frame => frame.kind === 'identity' && frame.ok));
  let serial = 0;
  return {
    child, frames,
    async call(method, params, ok = true) {
      const id = 'ui-e2e-' + (++serial);
      child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
      await until('desktop ' + method, () => frames.some(frame => frame.id === id), 35000);
      const response = frames.find(frame => frame.id === id);
      assert.equal(response.ok, ok, response.error);
      return response.data;
    },
  };
}
async function messages(user) { return (await ctl(user, ['messages', '--json'])).messages; }
async function received(user, text) {
  await until(user.name + ' receives ' + text, async () => (await messages(user)).some(message => message.text === text));
}

try {
  transport = await relay();
  const keyPath = join(scratch, 'server.key');
  const storagePath = join(scratch, 'storage.key');
  await writeFile(keyPath, '07'.repeat(32), { mode: 0o600 });
  await writeFile(storagePath, '42'.repeat(32), { mode: 0o600 });
  const server = processFor(join(bins, 'omachat-serverd'), [
    '--data-dir', join(scratch, 'server'), '--server-key-file', keyPath,
    '--storage-key-file', storagePath, '--listen', '127.0.0.1:0',
  ]);
  await until('handle server ready', () => {
    if (server.spawnError) throw server.spawnError;
    if (server.exitCode !== null) throw new Error(server.errors);
    return /server public key [0-9a-f]{64}/.test(server.errors);
  });
  const address = server.errors.match(/listening on (127\.0\.0\.1:\d+)/)[1];
  const pin = server.errors.match(/server public key ([0-9a-f]{64})/)[1];
  const alice = await user('alice', 'ws://' + address, pin);
  const bob = await user('bob', 'ws://' + address, pin);
  const aliceIdentity = await ctl(alice, ['chat-prepare', '--json']);
  const desktop = await bridge(bob);
  const bobIdentity = await ctl(bob, ['identity', 'show']);
  for (const [person, identity] of [[alice, aliceIdentity], [bob, bobIdentity]]) {
    await ctl(person, ['hosted-claim-handle', person.name, '--json']);
    await ctl(person, ['identity', 'bind']);
    const response = await fetch('http://' + address + '/.well-known/nostr.json?name=' + person.name);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('access-control-allow-origin'), '*');
    assert.equal((await response.json()).names[person.name], identity.pubkey);
    const probe = processFor('python3', [
      'scripts/verify-nip05.py', person.name + '@omachat.test', identity.pubkey,
      '--test-base-url', 'http://' + address,
    ]);
    await finish(probe);
    assert.equal(probe.exitCode, 0, probe.errors);
  }
  console.log('PASS: fresh identities, claimed handles, signed bindings and real NIP-05 HTTP endpoint');

  await desktop.call('contacts-add', { peer: aliceIdentity.npub });
  const terminal = processFor(join(bins, 'omachat'), ['--socket', alice.socket]);
  await until('terminal connected', () => terminal.output.includes(aliceIdentity.npub.slice(0, 16)));
  terminal.stdin.write('/contact add ' + bobIdentity.npub + '\n');
  await until('terminal contact', async () => (await ctl(alice, ['contacts-list', '--json'])).contacts.length === 1);
  await until('terminal contact rendered', () => terminal.output.includes(bobIdentity.npub.slice(0, 16)));
  terminal.stdin.write('terminal-to-desktop\n');
  await received(bob, 'terminal-to-desktop');
  await until('desktop live incoming event', () => desktop.frames.some(frame => frame.kind === 'event' && frame.data.payload.text === 'terminal-to-desktop'));
  await desktop.call('send', { peer: aliceIdentity.npub, text: 'desktop-to-terminal' });
  await received(alice, 'desktop-to-terminal');
  await until('terminal renders reply', () => terminal.output.includes('desktop-to-terminal'));
  console.log('PASS: terminal and desktop adapter exchange live DMs both ways');

  transport.reject(true);
  await desktop.call('send', { peer: aliceIdentity.npub, text: 'must-not-be-sent' }, false);
  assert.equal((await messages(bob)).some(message => message.text === 'must-not-be-sent'), false);
  transport.reject(false);
  await stop(desktop.child);
  await stop(bob.child);
  await ctl(alice, ['send', bobIdentity.npub, 'while-bob-offline', '--json']);
  await startDaemon(bob);
  const restoredDesktop = await bridge(bob);
  await received(bob, 'while-bob-offline');
  assert.equal((await ctl(bob, ['identity', 'show'])).npub, bobIdentity.npub);
  assert.equal((await ctl(bob, ['contacts-list', '--json'])).contacts[0].pubkey, aliceIdentity.pubkey);
  assert.equal((await messages(bob)).filter(message => message.text === 'desktop-to-terminal').length, 1);
  await ctl(bob, ['relays-set', transport.url, '--json']);
  const beforeReconnect = transport.requests;
  transport.disconnect();
  await until('relay subscriptions replay after disconnect', () => transport.requests >= beforeReconnect + 2);
  transport.replay();
  await restoredDesktop.call('send', { peer: aliceIdentity.npub, text: 'after-reconnect' });
  await received(alice, 'after-reconnect');
  await delay(300);
  for (const person of [alice, bob]) {
    const rows = await messages(person);
    assert.equal(new Set(rows.map(row => row.id)).size, rows.length);
  }
  console.log('PASS: rejection, offline delivery, restart, persisted identity/history, reconnect and replay deduplication');

  const secret = generateSecretKey();
  const nsec = nsecEncode(secret);
  secrets.push(nsec);
  const pubkey = getPublicKey(secret);
  const charlie = await user('charlie', 'ws://' + address, pin);
  await ctl(charlie, ['identity', 'import', nsec]);
  assert.equal((await ctl(charlie, ['identity', 'show'])).npub, npubEncode(pubkey));
  const exported = await ctl(charlie, ['identity', 'export'], 0, true);
  assert.equal(exported.nsec, nsec);
  await stop(charlie.child);
  external = new WebSocket(transport.url);
  await once(external, 'open');
  const inbox = [];
  external.on('message', data => inbox.push(JSON.parse(data)));
  external.send(JSON.stringify(['REQ', 'external', { kinds: [1059], '#p': [pubkey] }]));
  await until('independent inbox ready', () => inbox.some(frame => frame[0] === 'EOSE'));
  await ctl(alice, ['send', npubEncode(pubkey), 'omachat-to-nostr-tools', '--json']);
  await until('independent client receives', () => inbox.some(frame => frame[0] === 'EVENT'));
  const envelope = inbox.find(frame => frame[0] === 'EVENT')[2];
  assert.equal(verifyEvent(envelope), true);
  const rumor = unwrapEvent(envelope, secret);
  assert.equal(rumor.pubkey, aliceIdentity.pubkey);
  assert.equal(rumor.content, 'omachat-to-nostr-tools');
  const reply = wrapEvent(secret, { publicKey: bobIdentity.pubkey }, 'nostr-tools-to-omachat');
  external.send(JSON.stringify(['EVENT', reply]));
  await received(bob, 'nostr-tools-to-omachat');
  const incoming = (await messages(bob)).find(message => message.text === 'nostr-tools-to-omachat');
  assert.equal(incoming.peer, pubkey);
  console.log('PASS: identity import/export and bidirectional NIP-17/44/59 interoperability with nostr-tools 2.25.2');

  for (const child of transcripts) {
    for (const secret of secrets) assert.equal((child.output + child.errors).includes(secret), false, 'secret leaked into client output');
  }
  console.log('PASS: no private identity in ordinary client output');
} finally {
  external?.terminate();
  await Promise.all([...children].map(stop));
  if (transport) await transport.close();
  await rm(scratch, { recursive: true, force: true });
}
