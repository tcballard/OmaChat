// NIP-19/NIP-21 display identifiers only. All IPC still uses hexadecimal keys.
// No relay hints are followed and no secret key is accepted or retained here.
var alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function polymod(words) {
    var check = 1;
    var generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    words.forEach(function(word) {
        var top = check >>> 25;
        check = ((check & 0x1ffffff) << 5) ^ word;
        for (var i = 0; i < 5; i++) if ((top >>> i) & 1) check ^= generators[i];
    });
    return check >>> 0;
}
function expand(prefix) {
    var high = [], low = [];
    for (var i = 0; i < prefix.length; i++) { high.push(prefix.charCodeAt(i) >>> 5); low.push(prefix.charCodeAt(i) & 31); }
    return high.concat([0], low);
}
function convert(data, from, to, pad) {
    var acc = 0, bits = 0, out = [], mask = (1 << to) - 1;
    data.forEach(function(value) {
        if (value < 0 || (value >>> from)) throw new Error("Invalid contact encoding.");
        acc = ((acc << from) | value) & ((1 << (from + to - 1)) - 1);
        bits += from;
        while (bits >= to) { bits -= to; out.push((acc >>> bits) & mask); }
    });
    if (pad) { if (bits) out.push((acc << (to - bits)) & mask); }
    else if (bits >= from || ((acc << (to - bits)) & mask)) throw new Error("Invalid contact padding.");
    return out;
}
function encode(prefix, bytes) {
    var words = convert(bytes, 8, 5, true);
    var sum = polymod(expand(prefix).concat(words, [0, 0, 0, 0, 0, 0])) ^ 1;
    for (var i = 0; i < 6; i++) words.push((sum >>> (5 * (5 - i))) & 31);
    return prefix + "1" + words.map(function(w) { return alphabet[w]; }).join("");
}
function hex(bytes) { return bytes.map(function(b) { return ("0" + b.toString(16)).slice(-2); }).join(""); }
function npub(key) {
    if (!/^[0-9a-fA-F]{64}$/.test(key)) return "";
    var bytes = [];
    for (var i = 0; i < key.length; i += 2) bytes.push(parseInt(key.slice(i, i + 2), 16));
    return encode("npub", bytes);
}
function parse(input) {
    if (typeof input !== "string" || input.length > 5000) throw new Error("Contact links must be at most 5,000 characters.");
    var value = input.trim(), uri = /^nostr:/i.test(value);
    if (uri) value = value.slice(6);
    if (/^nsec1/i.test(value)) throw new Error("That is a private key. Use your contact’s npub public key instead.");
    if (!uri) {
        var bare = value.replace(/^dm:/, "");
        if (/^[0-9a-fA-F]{64}$/.test(bare)) return {key:bare.toLowerCase(), format:"Public key", hintsIgnored:false};
    }
    if (value !== value.toLowerCase() && value !== value.toUpperCase()) throw new Error("Contact link mixes upper and lower case.");
    value = value.toLowerCase();
    var split = value.lastIndexOf("1"), prefix = value.slice(0, split);
    if (prefix !== "npub" && prefix !== "nprofile") throw new Error("Use an npub, nprofile, nostr: contact link, or hexadecimal public key.");
    var words = value.slice(split + 1).split("").map(function(c) { return alphabet.indexOf(c); });
    if (words.length < 7 || words.some(function(w) { return w < 0; }) || polymod(expand(prefix).concat(words)) !== 1) throw new Error("Contact checksum failed. Ask your contact to copy the link again.");
    var bytes = convert(words.slice(0, -6), 5, 8, false), key = null, hints = false;
    if (prefix === "npub") {
        if (bytes.length !== 32) throw new Error("An npub must contain a 32-byte public key.");
        key = bytes;
    } else {
        for (var offset = 0; offset < bytes.length;) {
            if (offset + 2 > bytes.length) throw new Error("Truncated contact metadata.");
            var type = bytes[offset++], length = bytes[offset++];
            if (offset + length > bytes.length) throw new Error("Truncated contact metadata.");
            if (type === 0) {
                if (key || length !== 32) throw new Error("A profile must contain exactly one public key.");
                key = bytes.slice(offset, offset + length);
            }
            if (type === 1) hints = true;
            offset += length; // Ignore unknown TLVs as required by NIP-19.
        }
        if (!key) throw new Error("This profile has no public key.");
    }
    return {key:hex(key), format:prefix === "npub" ? "npub public key" : "Nostr profile", hintsIgnored:hints};
}
function preview(input) {
    if (!input.trim()) return {key:"", error:""};
    try { return parse(input); } catch (error) { return {key:"", error:error.message}; }
}
