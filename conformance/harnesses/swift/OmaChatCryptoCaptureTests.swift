// Capture-only test copied into the pinned bitchat Swift test target by CI.
// Every key, message, timestamp, nonce, and geohash below is synthetic.

import BitFoundation
import CryptoKit
import Foundation
import P256K
import Testing
@testable import bitchat

struct OmaChatCryptoCaptureTests {
    private let senderPrivate = Data(repeating: 0x11, count: 32)
    private let recipientPrivate = Data(repeating: 0x22, count: 32)
    private let wrapPrivate = Data(repeating: 0x33, count: 32)

    @Test func captureDeterministicCryptoVectors() throws {
        let root = try captureRoot()
        try captureGeohashIdentity(at: root)
        try captureNIP13Policy(at: root)

        let tagless = try makePrivateEnvelope(
            innerTags: [],
            content: "omachat synthetic tagless message",
            sealNonce: Data((0x00..<0x18).map(UInt8.init)),
            wrapNonce: Data((0x18..<0x30).map(UInt8.init)),
            sealAux: Data(repeating: 0x55, count: 32),
            wrapAux: Data(repeating: 0x66, count: 32)
        )
        try capturePrivateEnvelope(
            tagless,
            fixtureID: "swift-nostr-private-envelope-tagless-v1",
            at: root
        )
        try captureKeySchedule(tagless, at: root)

        let androidShape = try makePrivateEnvelope(
            innerTags: [["p", tagless.recipient.publicKeyHex]],
            content: "omachat synthetic android-shape message",
            sealNonce: Data((0x40..<0x58).map(UInt8.init)),
            wrapNonce: Data((0x58..<0x70).map(UInt8.init)),
            sealAux: Data(repeating: 0x77, count: 32),
            wrapAux: Data(repeating: 0x88, count: 32)
        )
        try capturePrivateEnvelope(
            androidShape,
            fixtureID: "swift-nostr-private-envelope-android-shape-v1",
            at: root
        )

        try captureNoiseXX(at: root)
        try captureCourierVectors(at: root)
    }

    // MARK: - Per-geohash identity

    private func captureGeohashIdentity(at root: URL) throws {
        let seed = Data(repeating: 0x44, count: 32)
        let geohash = "zzzzzz" // synthetic sentinel cell, not a user location
        let keychain = MockKeychain()
        keychain.save(
            key: "nostr-device-seed",
            data: seed,
            service: "chat.bitchat.nostr",
            accessible: nil
        )

        let identity = try NostrIdentityBridge(keychain: keychain)
            .deriveIdentity(forGeohash: geohash)

        var selectedIteration: UInt32?
        for iteration in UInt32(0)..<UInt32(10) {
            var input = Data(geohash.utf8)
            appendBigEndian(iteration, to: &input)
            let candidate = Data(HMAC<CryptoKit.SHA256>.authenticationCode(
                for: input,
                using: SymmetricKey(data: seed)
            ))
            if candidate == identity.privateKey {
                selectedIteration = iteration
                break
            }
        }

        try writeFixture(
            "swift-geohash-identity-v1",
            root: root,
            inputs: [
                "device_seed_hex": seed.hexString(),
                "geohash_utf8": geohash,
                "geohash_disclosure": "synthetic sentinel; not derived from a physical location",
                "candidate_input_layout": "geohash UTF-8 || iteration UInt32 big-endian",
            ],
            intermediates: [
                "selected_iteration": selectedIteration.map(Int.init) ?? -1,
                "selected_iteration_endianness": "big-endian",
                "candidate_algorithm": "HMAC-SHA256(key=device seed, message=candidate input)",
            ],
            outputs: [
                "private_key_hex": identity.privateKey.hexString(),
                "xonly_public_key_hex": identity.publicKey.hexString(),
                "npub": identity.npub,
            ]
        )
    }

    // MARK: - NIP-13 policy

    private func captureNIP13Policy(at root: URL) throws {
        let identity = try NostrIdentity(privateKeyData: senderPrivate)
        let createdAt = 1_700_000_123
        let baseTags = [["g", "zzzzzz"], ["n", "synthetic"]]
        let content = "omachat synthetic pow message"
        let target = NostrPoW.targetBits

        var nonce: UInt64 = 0
        var eventID = Data()
        while true {
            let nonceTag = ["nonce", String(format: "%016llx", nonce), String(target)]
            eventID = try eventIDHash(
                pubkey: identity.publicKeyHex,
                createdAt: createdAt,
                kind: NostrProtocol.EventKind.ephemeralEvent.rawValue,
                tags: baseTags + [nonceTag],
                content: content
            )
            if NostrPoW.leadingZeroBits(eventID) >= target {
                break
            }
            nonce &+= 1
        }

        let nonceTag = ["nonce", String(format: "%016llx", nonce), String(target)]
        let tags = baseTags + [nonceTag]
        let idHex = eventID.hexString()
        let actualDifficulty = NostrPoW.leadingZeroBits(eventID)
        let overclaim = min(actualDifficulty + 1, 256)

        #expect(NostrPoW.validatedDifficulty(idHex: idHex, tags: tags) == target)
        #expect(NostrPoW.validatedDifficulty(idHex: idHex, tags: baseTags) == 0)
        #expect(NostrPoW.validatedDifficulty(
            idHex: idHex,
            tags: baseTags + [["nonce", nonceTag[1], String(overclaim)]]
        ) == 0)

        try writeFixture(
            "swift-nip13-policy-v1",
            root: root,
            inputs: [
                "pubkey_hex": identity.publicKeyHex,
                "created_at": createdAt,
                "created_at_unit": "whole seconds since Unix epoch",
                "kind": NostrProtocol.EventKind.ephemeralEvent.rawValue,
                "base_tags": baseTags,
                "content": content,
                "deterministic_capture_start_nonce": "0000000000000000",
            ],
            intermediates: [
                "canonical_serialization": [0, identity.publicKeyHex, createdAt,
                    NostrProtocol.EventKind.ephemeralEvent.rawValue, tags, content],
                "nonce_encoding": "16 lowercase hexadecimal digits",
                "event_id_hash": "SHA-256 of compact NIP-01 JSON",
                "mined_nonce_tag": nonceTag,
            ],
            outputs: [
                "event_id_hex": idHex,
                "actual_leading_zero_bits": actualDifficulty,
                "creation_policy": [
                    "target_bits": NostrPoW.targetBits,
                    "main_time_cap_seconds": NostrPoW.miningTimeCap,
                    "fallback_time_cap_seconds": 0.15,
                    "fallback_target_rule": "halve committed target until a bounded attempt succeeds",
                    "production_start_nonce": "random UInt64; deterministic capture starts at zero",
                ],
                "acceptance_policy": [
                    "rate_limit_bypass_bits": NostrPoW.rateLimitBypassBits,
                    "valid_committed_score": NostrPoW.validatedDifficulty(idHex: idHex, tags: tags),
                    "missing_nonce_score": NostrPoW.validatedDifficulty(idHex: idHex, tags: baseTags),
                    "overclaimed_target": overclaim,
                    "overclaimed_score": NostrPoW.validatedDifficulty(
                        idHex: idHex,
                        tags: baseTags + [["nonce", nonceTag[1], String(overclaim)]]
                    ),
                    "work_above_commitment": "does not increase the validated score",
                    "inbound_action": "score only; never hard-reject solely for missing work",
                ],
            ]
        )
    }

    // MARK: - Nostr private envelopes

    private struct PrivateEnvelopeCapture {
        let sender: NostrIdentity
        let recipient: NostrIdentity
        let wrap: NostrIdentity
        let content: String
        let innerTags: [[String]]
        let rumor: NostrEvent
        let rumorJSON: String
        let sealSharedPoint: Data
        let sealKey: Data
        let sealNonce: Data
        let seal: NostrEvent
        let sealJSON: String
        let wrapSharedPoint: Data
        let wrapKey: Data
        let wrapNonce: Data
        let giftWrap: NostrEvent
    }

    private func makePrivateEnvelope(
        innerTags: [[String]],
        content: String,
        sealNonce: Data,
        wrapNonce: Data,
        sealAux: Data,
        wrapAux: Data
    ) throws -> PrivateEnvelopeCapture {
        let sender = try NostrIdentity(privateKeyData: senderPrivate)
        let recipient = try NostrIdentity(privateKeyData: recipientPrivate)
        let wrap = try NostrIdentity(privateKeyData: wrapPrivate)

        let rumor = NostrEvent(
            pubkey: sender.publicKeyHex,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            kind: .dm,
            tags: innerTags,
            content: content
        )
        let rumorJSON = try deterministicEventJSONString(rumor)
        let (sealSharedPoint, sealKey) = try privateEnvelopeKey(
            privateKey: sender.privateKey,
            recipientXOnlyPublicKey: recipient.publicKey
        )
        let sealCiphertext = try privateEnvelopeEncrypt(
            rumorJSON,
            key: sealKey,
            nonce: sealNonce
        )
        let unsignedSeal = NostrEvent(
            pubkey: sender.publicKeyHex,
            createdAt: Date(timeIntervalSince1970: 1_699_999_500),
            kind: .seal,
            tags: [],
            content: sealCiphertext
        )
        let seal = try deterministicSign(unsignedSeal, privateKey: sender.privateKey, aux: sealAux)
        let sealJSON = try deterministicEventJSONString(seal)

        let (wrapSharedPoint, wrapKey) = try privateEnvelopeKey(
            privateKey: wrap.privateKey,
            recipientXOnlyPublicKey: recipient.publicKey
        )
        let giftCiphertext = try privateEnvelopeEncrypt(
            sealJSON,
            key: wrapKey,
            nonce: wrapNonce
        )
        let unsignedGiftWrap = NostrEvent(
            pubkey: wrap.publicKeyHex,
            createdAt: Date(timeIntervalSince1970: 1_700_000_600),
            kind: .giftWrap,
            tags: [["p", recipient.publicKeyHex]],
            content: giftCiphertext
        )
        let giftWrap = try deterministicSign(
            unsignedGiftWrap,
            privateKey: wrap.privateKey,
            aux: wrapAux
        )

        let opened = try NostrProtocol.decryptPrivateMessage(
            giftWrap: giftWrap,
            recipientIdentity: recipient
        )
        #expect(opened.content == content)
        #expect(opened.senderPubkey == sender.publicKeyHex)
        #expect(opened.timestamp == rumor.created_at)

        return PrivateEnvelopeCapture(
            sender: sender,
            recipient: recipient,
            wrap: wrap,
            content: content,
            innerTags: innerTags,
            rumor: rumor,
            rumorJSON: rumorJSON,
            sealSharedPoint: sealSharedPoint,
            sealKey: sealKey,
            sealNonce: sealNonce,
            seal: seal,
            sealJSON: sealJSON,
            wrapSharedPoint: wrapSharedPoint,
            wrapKey: wrapKey,
            wrapNonce: wrapNonce,
            giftWrap: giftWrap
        )
    }

    private func captureKeySchedule(_ capture: PrivateEnvelopeCapture, at root: URL) throws {
        try writeFixture(
            "swift-nostr-private-envelope-key-schedule-v1",
            root: root,
            inputs: [
                "sender_private_key_hex": capture.sender.privateKey.hexString(),
                "sender_xonly_public_key_hex": capture.sender.publicKeyHex,
                "recipient_private_key_hex": capture.recipient.privateKey.hexString(),
                "recipient_xonly_public_key_hex": capture.recipient.publicKeyHex,
                "recipient_sec1_lift_hex": "02" + capture.recipient.publicKeyHex,
                "recipient_sec1_lift_rule": "x-only key lifted with even-Y compressed prefix 0x02",
            ],
            intermediates: [
                "ecdh_shared_point_compressed_hex": capture.sealSharedPoint.hexString(),
                "ecdh_shared_point_bytes": capture.sealSharedPoint.count,
                "ecdh_shared_point_encoding": "SEC1 compressed point: parity prefix || X coordinate",
                "hkdf_hash": "SHA-256",
                "hkdf_salt_hex": "",
                "hkdf_info_utf8": "nip44-v2",
                "hkdf_output_bytes": 32,
            ],
            outputs: [
                "private_envelope_key_hex": capture.sealKey.hexString(),
                "byte_order": "octet strings are recorded in exact API/wire order; no integer reinterpretation",
            ]
        )
    }

    private func capturePrivateEnvelope(
        _ capture: PrivateEnvelopeCapture,
        fixtureID: String,
        at root: URL
    ) throws {
        try writeFixture(
            fixtureID,
            root: root,
            inputs: [
                "sender_private_key_hex": capture.sender.privateKey.hexString(),
                "sender_xonly_public_key_hex": capture.sender.publicKeyHex,
                "recipient_private_key_hex": capture.recipient.privateKey.hexString(),
                "recipient_xonly_public_key_hex": capture.recipient.publicKeyHex,
                "one_time_private_key_hex": capture.wrap.privateKey.hexString(),
                "one_time_xonly_public_key_hex": capture.wrap.publicKeyHex,
                "content_utf8": capture.content,
                "inner_tags": capture.innerTags,
                "rumor_created_at": capture.rumor.created_at,
                "seal_created_at": capture.seal.created_at,
                "gift_wrap_created_at": capture.giftWrap.created_at,
                "timestamps_unit": "whole seconds since Unix epoch",
                "seal_nonce_hex": capture.sealNonce.hexString(),
                "gift_wrap_nonce_hex": capture.wrapNonce.hexString(),
            ],
            intermediates: [
                "rumor_kind": NostrProtocol.EventKind.dm.rawValue,
                "rumor_event": try eventObject(capture.rumor),
                "rumor_json_utf8_hex": Data(capture.rumorJSON.utf8).hexString(),
                "seal_ecdh_shared_point_compressed_hex": capture.sealSharedPoint.hexString(),
                "seal_hkdf_key_hex": capture.sealKey.hexString(),
                "seal_event": try eventObject(capture.seal),
                "seal_json_utf8_hex": Data(capture.sealJSON.utf8).hexString(),
                "gift_wrap_ecdh_shared_point_compressed_hex": capture.wrapSharedPoint.hexString(),
                "gift_wrap_hkdf_key_hex": capture.wrapKey.hexString(),
                "ciphertext_layout": "ASCII v2: || base64url(no padding, nonce24 || ciphertext || Poly1305 tag16)",
                "capture_nested_json_order": "lexicographically sorted object keys; JSON member order is not a protocol semantic",
            ],
            outputs: [
                "gift_wrap_event": try eventObject(capture.giftWrap),
                "authenticated_open": [
                    "content": capture.content,
                    "sender_pubkey": capture.sender.publicKeyHex,
                    "true_created_at": capture.rumor.created_at,
                ],
            ]
        )
    }

    private func privateEnvelopeKey(
        privateKey: Data,
        recipientXOnlyPublicKey: Data
    ) throws -> (sharedPoint: Data, key: Data) {
        let schnorrPrivate = try P256K.Schnorr.PrivateKey(
            dataRepresentation: privateKey
        )
        let agreementPrivate = try P256K.KeyAgreement.PrivateKey(
            dataRepresentation: schnorrPrivate.dataRepresentation
        )
        let compressedPublic = Data([0x02]) + recipientXOnlyPublicKey
        let agreementPublic = try P256K.KeyAgreement.PublicKey(
            dataRepresentation: compressedPublic,
            format: .compressed
        )
        let shared = try agreementPrivate.sharedSecretFromKeyAgreement(
            with: agreementPublic,
            format: .compressed
        )
        let sharedPoint = shared.withUnsafeBytes { Data($0) }
        let key = HKDF<CryptoKit.SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedPoint),
            salt: Data(),
            info: Data("nip44-v2".utf8),
            outputByteCount: 32
        ).withUnsafeBytes { Data($0) }
        return (sharedPoint, key)
    }

    private func privateEnvelopeEncrypt(_ plaintext: String, key: Data, nonce: Data) throws -> String {
        #expect(nonce.count == 24)
        let sealed = try XChaCha20Poly1305Compat.seal(
            plaintext: Data(plaintext.utf8),
            key: key,
            nonce24: nonce
        )
        let combined = nonce + sealed.ciphertext + sealed.tag
        return "v2:" + Base64URLCoding.encode(combined)
    }

    private func deterministicSign(
        _ event: NostrEvent,
        privateKey: Data,
        aux: Data
    ) throws -> NostrEvent {
        #expect(aux.count == 32)
        let serialized: [Any] = [
            0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
        ]
        let canonical = try JSONSerialization.data(
            withJSONObject: serialized,
            options: [.withoutEscapingSlashes]
        )
        let eventHash = Data(CryptoKit.SHA256.hash(data: canonical))
        let key = try P256K.Schnorr.PrivateKey(dataRepresentation: privateKey)
        var message = [UInt8](eventHash)
        var auxiliary = [UInt8](aux)
        let signature = try key.signature(message: &message, auxiliaryRand: &auxiliary)

        var signed = event
        signed.id = eventHash.hexString()
        signed.sig = signature.dataRepresentation.hexString()
        #expect(signed.isValidSignature())
        return signed
    }

    private func deterministicEventJSONString(_ event: NostrEvent) throws -> String {
        var object: [String: Any] = [
            "id": event.id,
            "pubkey": event.pubkey,
            "created_at": event.created_at,
            "kind": event.kind,
            "tags": event.tags,
            "content": event.content,
        ]
        if let signature = event.sig {
            object["sig"] = signature
        }
        let data = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        return try #require(String(data: data, encoding: .utf8))
    }

    // MARK: - Noise XX

    private func captureNoiseXX(at root: URL) throws {
        let vectors = try loadNoiseVectors()
        let vector = try #require(vectors.first)
        let initStatic = try #require(Data(hex: vector.init_static))
        let initEphemeral = try #require(Data(hex: vector.init_ephemeral))
        let respStatic = try #require(Data(hex: vector.resp_static))
        let respEphemeral = try #require(Data(hex: vector.resp_ephemeral))
        let prologue = try #require(Data(hex: vector.init_prologue))

        let initiator = NoiseHandshakeState(
            role: .initiator,
            pattern: .XX,
            keychain: MockKeychain(),
            localStaticKey: try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: initStatic),
            prologue: prologue,
            predeterminedEphemeralKey: try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: initEphemeral
            )
        )
        let responder = NoiseHandshakeState(
            role: .responder,
            pattern: .XX,
            keychain: MockKeychain(),
            localStaticKey: try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: respStatic),
            prologue: prologue,
            predeterminedEphemeralKey: try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: respEphemeral
            )
        )

        var handshakeMessages: [[String: Any]] = []
        for index in 0..<3 {
            let item = vector.messages[index]
            let payload = try #require(Data(hex: item.payload))
            let expected = try #require(Data(hex: item.ciphertext))
            let sender = index % 2 == 0 ? initiator : responder
            let receiver = index % 2 == 0 ? responder : initiator
            let ciphertext = try sender.writeMessage(payload: payload)
            #expect(ciphertext == expected)
            #expect(try receiver.readMessage(ciphertext) == payload)
            handshakeMessages.append([
                "message_number": index + 1,
                "direction": index % 2 == 0 ? "initiator-to-responder" : "responder-to-initiator",
                "payload_hex": payload.hexString(),
                "ciphertext_hex": ciphertext.hexString(),
            ])
        }

        let initiatorHash = initiator.getHandshakeHash()
        let responderHash = responder.getHandshakeHash()
        #expect(initiatorHash == responderHash)
        if let expectedHash = vector.handshake_hash {
            #expect(initiatorHash.hexString() == expectedHash)
        }

        let (initSend, initReceive, _) = try initiator.getTransportCiphers(useExtractedNonce: false)
        let (respSend, respReceive, _) = try responder.getTransportCiphers(useExtractedNonce: false)
        var counters = ["initiator": 0, "responder": 0]
        var transportMessages: [[String: Any]] = []

        for index in 3..<vector.messages.count {
            let item = vector.messages[index]
            let payload = try #require(Data(hex: item.payload))
            let expected = try #require(Data(hex: item.ciphertext))
            let transportIndex = index - 3
            let responderSends = transportIndex % 2 == 0
            let senderName = responderSends ? "responder" : "initiator"
            let sender = responderSends ? respSend : initSend
            let receiver = responderSends ? initReceive : respReceive
            let counter = counters[senderName] ?? 0
            let ciphertext = try sender.encrypt(plaintext: payload)
            #expect(ciphertext == expected)
            #expect(try receiver.decrypt(ciphertext: ciphertext) == payload)
            counters[senderName] = counter + 1
            transportMessages.append([
                "message_number": index + 1,
                "direction": responderSends ? "responder-to-initiator" : "initiator-to-responder",
                "counter_before": counter,
                "counter_encoding": "Noise 96-bit nonce: 4 zero bytes || UInt64 little-endian",
                "payload_hex": payload.hexString(),
                "ciphertext_hex": ciphertext.hexString(),
            ])
        }

        try writeFixture(
            "swift-noise-xx-transcript-v1",
            root: root,
            inputs: [
                "protocol_name": vector.protocol_name,
                "prologue_hex": vector.init_prologue,
                "initiator_static_private_hex": vector.init_static,
                "initiator_ephemeral_private_hex": vector.init_ephemeral,
                "responder_static_private_hex": vector.resp_static,
                "responder_ephemeral_private_hex": vector.resp_ephemeral,
                "source_vector_index": 0,
                "source_vector_provenance": "cacophony vector embedded in pinned Swift tests",
            ],
            intermediates: [
                "handshake_messages": handshakeMessages,
                "handshake_hash_hex": initiatorHash.hexString(),
            ],
            outputs: [
                "transport_messages": transportMessages,
                "final_send_counters": counters,
                "transport_ciphertext_layout": "ciphertext || Poly1305 tag16; no explicit counter prefix",
            ]
        )
    }

    private func loadNoiseVectors() throws -> [NoiseTestVector] {
        #if SWIFT_PACKAGE
        let bundle = Bundle.module
        #else
        let bundle = Bundle(for: MockKeychain.self)
        #endif
        let url = try #require(bundle.url(
            forResource: "NoiseTestVectors",
            withExtension: "json"
        ))
        return try JSONDecoder().decode(
            [NoiseTestVector].self,
            from: Data(contentsOf: url)
        )
    }

    // MARK: - Courier vectors

    private func captureCourierVectors(at root: URL) throws {
        let aliceStatic = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data((0x01...0x20).map(UInt8.init))
        )
        let bobStatic = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data((0x21...0x40).map(UInt8.init))
        )
        let v1Ephemeral = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data((0x41...0x60).map(UInt8.init))
        )
        let v1Payload = Data("omachat synthetic courier v1".utf8)
        let v1Prologue = Data("bitchat-courier-v1".utf8)
        let v1Ciphertext = try noiseXSeal(
            payload: v1Payload,
            senderStatic: aliceStatic,
            recipientStatic: bobStatic,
            ephemeral: v1Ephemeral,
            prologue: v1Prologue
        )
        let day: UInt32 = 20_000
        let routeTag = CourierEnvelope.recipientTag(
            noiseStaticKey: bobStatic.publicKey.rawRepresentation,
            epochDay: day
        )
        let v1Envelope = CourierEnvelope(
            recipientTag: routeTag,
            expiry: 1_700_086_400_000,
            ciphertext: v1Ciphertext,
            copies: 1
        )
        let v1Encoded = try #require(v1Envelope.encode())
        #expect(CourierEnvelope.decode(v1Encoded) == v1Envelope)

        try writeFixture(
            "swift-courier-static-v1",
            root: root,
            inputs: [
                "sender_static_private_hex": aliceStatic.rawRepresentation.hexString(),
                "recipient_static_private_hex": bobStatic.rawRepresentation.hexString(),
                "recipient_static_public_hex": bobStatic.publicKey.rawRepresentation.hexString(),
                "ephemeral_private_hex": v1Ephemeral.rawRepresentation.hexString(),
                "prologue_utf8": String(decoding: v1Prologue, as: UTF8.self),
                "payload_utf8": String(decoding: v1Payload, as: UTF8.self),
                "epoch_day": Int(day),
                "epoch_day_endianness": "UInt32 big-endian in day-tag HMAC message",
                "tag_context_utf8": "bitchat-courier-tag-v1",
                "expiry_milliseconds": 1_700_086_400_000 as UInt64,
                "expiry_milliseconds_endianness": "UInt64 big-endian in courier TLV",
            ],
            intermediates: [
                "noise_pattern": "X",
                "noise_ciphertext_hex": v1Ciphertext.hexString(),
                "recipient_tag_hex": routeTag.hexString(),
                "recipient_tag_formula": "HMAC-SHA256(key=recipient static public key, message=UTF8(bitchat-courier-tag-v1) || epochDayBE)[0..16]",
            ],
            outputs: [
                "courier_envelope_hex": v1Encoded.hexString(),
                "courier_envelope_layout": "TLVs: type UInt8 || length UInt16 big-endian || value",
                "seal_version": 1,
                "copies": 1,
                "prekey_id": "absent",
                "opened_payload_hex": v1Payload.hexString(),
                "authenticated_sender_static_public_hex": aliceStatic.publicKey.rawRepresentation.hexString(),
            ]
        )

        let prekeyID: UInt32 = 0xA1B2_C3D4
        let bobPrekey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data((0x61...0x80).map(UInt8.init))
        )
        let v2Ephemeral = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data((0x81...0xA0).map(UInt8.init))
        )
        var v2Prologue = Data("bitchat-prekey-v1".utf8)
        appendBigEndian(prekeyID, to: &v2Prologue)
        let v2Payload = Data("omachat synthetic courier v2 prekey".utf8)
        let v2Ciphertext = try noiseXSeal(
            payload: v2Payload,
            senderStatic: aliceStatic,
            recipientStatic: bobPrekey,
            ephemeral: v2Ephemeral,
            prologue: v2Prologue
        )
        let v2Envelope = CourierEnvelope(
            recipientTag: routeTag,
            expiry: 1_700_086_400_000,
            ciphertext: v2Ciphertext,
            copies: 4,
            prekeyID: prekeyID
        )
        let v2Encoded = try #require(v2Envelope.encode())
        #expect(CourierEnvelope.decode(v2Encoded) == v2Envelope)

        try writeFixture(
            "swift-courier-prekey-v2",
            root: root,
            inputs: [
                "sender_static_private_hex": aliceStatic.rawRepresentation.hexString(),
                "recipient_identity_static_public_hex": bobStatic.publicKey.rawRepresentation.hexString(),
                "recipient_prekey_private_hex": bobPrekey.rawRepresentation.hexString(),
                "recipient_prekey_public_hex": bobPrekey.publicKey.rawRepresentation.hexString(),
                "prekey_id": Int(prekeyID),
                "prekey_id_hex": String(format: "%08x", prekeyID),
                "prekey_id_endianness": "UInt32 big-endian in prologue and courier TLV",
                "ephemeral_private_hex": v2Ephemeral.rawRepresentation.hexString(),
                "prologue_hex": v2Prologue.hexString(),
                "payload_utf8": String(decoding: v2Payload, as: UTF8.self),
                "epoch_day": Int(day),
                "epoch_day_endianness": "UInt32 big-endian in day-tag HMAC message",
                "tag_context_utf8": "bitchat-courier-tag-v1",
                "expiry_milliseconds": 1_700_086_400_000 as UInt64,
                "expiry_milliseconds_endianness": "UInt64 big-endian in courier TLV",
            ],
            intermediates: [
                "noise_pattern": "X",
                "noise_ciphertext_hex": v2Ciphertext.hexString(),
                "recipient_tag_hex": routeTag.hexString(),
                "recipient_tag_key": "recipient long-term Noise static public key, not one-time prekey",
            ],
            outputs: [
                "courier_envelope_hex": v2Encoded.hexString(),
                "courier_envelope_layout": "TLVs: type UInt8 || length UInt16 big-endian || value",
                "seal_version": 2,
                "copies": 4,
                "prekey_id": Int(prekeyID),
                "opened_payload_hex": v2Payload.hexString(),
                "authenticated_sender_static_public_hex": aliceStatic.publicKey.rawRepresentation.hexString(),
            ]
        )

        let date = Date(timeIntervalSince1970: TimeInterval(day) * 86_400 + 43_210)
        let candidates = CourierEnvelope.candidateTags(
            noiseStaticKey: bobStatic.publicKey.rawRepresentation,
            around: date
        )
        #expect(candidates.count == 3)
        try writeFixture(
            "swift-courier-day-tags-v1",
            root: root,
            inputs: [
                "recipient_noise_static_public_hex": bobStatic.publicKey.rawRepresentation.hexString(),
                "timestamp_seconds": Int(date.timeIntervalSince1970),
                "timestamp_unit": "whole seconds since Unix epoch",
                "epoch_day": Int(day),
                "tag_context_utf8": "bitchat-courier-tag-v1",
                "epoch_day_endianness": "UInt32 big-endian",
            ],
            intermediates: [
                "hmac": "HMAC-SHA256",
                "hmac_key": "recipient Noise static public key bytes",
                "hmac_message": "tag context UTF-8 || epoch day UInt32 big-endian",
                "truncation": "first 16 bytes",
            ],
            outputs: [
                "previous_day": Int(day - 1),
                "previous_tag_hex": candidates[0].hexString(),
                "current_day": Int(day),
                "current_tag_hex": candidates[1].hexString(),
                "next_day": Int(day + 1),
                "next_tag_hex": candidates[2].hexString(),
                "candidate_order": ["previous", "current", "next"],
            ]
        )
    }

    private func noiseXSeal(
        payload: Data,
        senderStatic: Curve25519.KeyAgreement.PrivateKey,
        recipientStatic: Curve25519.KeyAgreement.PrivateKey,
        ephemeral: Curve25519.KeyAgreement.PrivateKey,
        prologue: Data
    ) throws -> Data {
        let initiator = NoiseHandshakeState(
            role: .initiator,
            pattern: .X,
            keychain: MockKeychain(),
            localStaticKey: senderStatic,
            remoteStaticKey: recipientStatic.publicKey,
            prologue: prologue,
            predeterminedEphemeralKey: ephemeral
        )
        let ciphertext = try initiator.writeMessage(payload: payload)

        let responder = NoiseHandshakeState(
            role: .responder,
            pattern: .X,
            keychain: MockKeychain(),
            localStaticKey: recipientStatic,
            prologue: prologue
        )
        let opened = try responder.readMessage(ciphertext)
        #expect(opened == payload)
        #expect(responder.getRemoteStaticPublicKey()?.rawRepresentation == senderStatic.publicKey.rawRepresentation)
        return ciphertext
    }

    // MARK: - Generic capture helpers

    private func captureRoot() throws -> URL {
        let value = try #require(ProcessInfo.processInfo.environment["OMACHAT_CAPTURE_DIR"])
        let root = URL(fileURLWithPath: value, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        return root
    }

    private func writeFixture(
        _ id: String,
        root: URL,
        inputs: [String: Any],
        intermediates: [String: Any],
        outputs: [String: Any]
    ) throws {
        let directory = root.appendingPathComponent(id, isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        try writeJSON(inputs, to: directory.appendingPathComponent("inputs.json"))
        try writeJSON(intermediates, to: directory.appendingPathComponent("intermediates.json"))
        try writeJSON(outputs, to: directory.appendingPathComponent("outputs.json"))
    }

    private func writeJSON(_ object: Any, to url: URL) throws {
        let data = try JSONSerialization.data(
            withJSONObject: object,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        var terminated = data
        terminated.append(0x0A)
        try terminated.write(to: url, options: .atomic)
    }

    private func eventObject(_ event: NostrEvent) throws -> [String: Any] {
        let data = try JSONEncoder().encode(event)
        return try #require(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
    }

    private func eventIDHash(
        pubkey: String,
        createdAt: Int,
        kind: Int,
        tags: [[String]],
        content: String
    ) throws -> Data {
        let serialized: [Any] = [0, pubkey, createdAt, kind, tags, content]
        let data = try JSONSerialization.data(
            withJSONObject: serialized,
            options: [.withoutEscapingSlashes]
        )
        return Data(CryptoKit.SHA256.hash(data: data))
    }

    private func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
    }
}
