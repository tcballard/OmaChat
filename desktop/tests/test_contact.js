const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const c = vm.createContext({});
vm.runInContext(fs.readFileSync(__dirname + '/../Contact.js', 'utf8'), c);
// Independent published NIP-19 vectors, not encode/decode self-consistency only.
const key='3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d';
const npub='npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6';
const profile='nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p';
assert.equal(c.npub(key),npub);
for (const input of [npub,npub.toUpperCase(),'nostr:'+npub,profile,'nostr:'+profile,key,'dm:'+key]) assert.equal(c.parse(input).key,key);
assert.equal(c.parse(profile).hintsIgnored,true);
assert.equal(c.parse('npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg').key,'7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e');
for(const input of ['nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5','nostr:nsec1secret','Npub'+npub.slice(4),npub.slice(0,-1)+'q','nostr:'+key,npub+'?relay=x','x'.repeat(5001),'https://example.com/'+npub]) assert.throws(()=>c.parse(input));
const bytes=Array.from(Buffer.from(key,'hex'));
assert.equal(c.parse(c.encode('nprofile',[99,2,4,5,0,32,...bytes])).key,key,'unknown TLV ignored');
for(const bytes2 of [[0,31,...bytes.slice(0,31)],[0,32,...bytes,0,32,...bytes],[1,1,5],[0,32,...bytes,1,4,5],[0]]) assert.throws(()=>c.parse(c.encode('nprofile',bytes2)));
assert.throws(()=>c.parse(c.encode('npub',[...bytes,1])));
assert.equal(c.preview('nostr:nsec1secret').key,'');
assert.match(c.preview('nostr:nsec1secret').error,/private key/);
console.log('PASS: published NIP-19 vectors, URI handling, checksum/case/size/metadata validation, secret-key rejection and ignored relay hints');
