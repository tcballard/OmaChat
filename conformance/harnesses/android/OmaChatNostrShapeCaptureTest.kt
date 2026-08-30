// Capture-only test copied into the pinned bitchat Android JVM test target by CI.
// It consumes deterministic Swift envelopes and records Android's accepted shapes.

package com.bitchat.android.nostr

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.JsonParser
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class OmaChatNostrShapeCaptureTest {
    private val gson: Gson = GsonBuilder().disableHtmlEscaping().create()
    private val prettyGson: Gson = GsonBuilder()
        .disableHtmlEscaping()
        .setPrettyPrinting()
        .create()

    @Test
    fun captureSupportedPrivateEnvelopeShapes() {
        val swiftRoot = File(requireEnv("OMACHAT_SWIFT_CAPTURE_DIR"))
        val outputRoot = File(requireEnv("OMACHAT_CAPTURE_DIR"))
        val fixtureRoot = File(outputRoot, "android-nostr-supported-shapes-v1")
        fixtureRoot.mkdirs()

        val taglessElement = loadGiftWrap(
            swiftRoot,
            "swift-nostr-private-envelope-tagless-v1"
        )
        val androidShapeElement = loadGiftWrap(
            swiftRoot,
            "swift-nostr-private-envelope-android-shape-v1"
        )
        val tagless = gson.fromJson(taglessElement, NostrEvent::class.java)
        val androidShape = gson.fromJson(androidShapeElement, NostrEvent::class.java)

        val recipientPrivateKey = "22".repeat(32)
        val recipient = NostrIdentity.fromPrivateKey(recipientPrivateKey)
        val taglessOpened = NostrProtocol.decryptPrivateMessage(tagless, recipient)
        val androidShapeOpened = NostrProtocol.decryptPrivateMessage(androidShape, recipient)

        assertNotNull(taglessOpened)
        assertNotNull(androidShapeOpened)
        assertEquals("omachat synthetic tagless message", taglessOpened?.first)
        assertEquals("omachat synthetic android-shape message", androidShapeOpened?.first)

        val sender = NostrIdentity.fromPrivateKey("11".repeat(32))
        val currentRumorBase = NostrEvent(
            pubkey = sender.publicKeyHex,
            createdAt = 1_700_000_000,
            kind = NostrKind.DIRECT_MESSAGE,
            tags = listOf(listOf("p", recipient.publicKeyHex)),
            content = "omachat synthetic android-created rumor"
        )
        val currentRumor = currentRumorBase.copy(id = currentRumorBase.computeEventIdHex())

        writeJson(
            File(fixtureRoot, "inputs.json"),
            linkedMapOf(
                "recipient_private_key_hex" to recipientPrivateKey,
                "recipient_xonly_public_key_hex" to recipient.publicKeyHex,
                "tagless_swift_gift_wrap_event" to taglessElement,
                "android_shape_swift_gift_wrap_event" to androidShapeElement,
                "input_provenance" to "deterministic envelopes captured by the pinned Swift build"
            )
        )

        writeJson(
            File(fixtureRoot, "outputs.json"),
            linkedMapOf(
                "accepted_shapes" to listOf(
                    linkedMapOf(
                        "name" to "released-swift-tagless-inner",
                        "inner_tags" to emptyList<List<String>>(),
                        "accepted" to true,
                        "content" to taglessOpened?.first,
                        "authenticated_sender_pubkey" to taglessOpened?.second,
                        "true_created_at" to taglessOpened?.third
                    ),
                    linkedMapOf(
                        "name" to "current-android-recipient-p-tag-inner",
                        "inner_tags" to listOf(listOf("p", recipient.publicKeyHex)),
                        "accepted" to true,
                        "content" to androidShapeOpened?.first,
                        "authenticated_sender_pubkey" to androidShapeOpened?.second,
                        "true_created_at" to androidShapeOpened?.third
                    )
                ),
                "current_android_created_inner_event" to gson.toJsonTree(currentRumor),
                "current_android_creation_shape" to linkedMapOf(
                    "kind" to NostrKind.DIRECT_MESSAGE,
                    "recipient_tag_location" to "exactly one inner p tag",
                    "inner_event_id" to "computed before encryption",
                    "signature" to "absent; sender authentication comes from the signed seal"
                ),
                "byte_order" to "Nostr fields are JSON; encrypted octet strings remain in the Swift fixture's exact wire order"
            )
        )
    }

    private fun loadGiftWrap(root: File, fixtureID: String): JsonElement {
        val outputs = File(File(root, fixtureID), "outputs.json")
        require(outputs.isFile) { "Missing Swift capture: ${outputs.path}" }
        val objectValue = outputs.reader().use { reader ->
            JsonParser.parseReader(reader).asJsonObject
        }
        return objectValue.get("gift_wrap_event")
    }

    private fun requireEnv(name: String): String =
        requireNotNull(System.getenv(name)) { "$name is required" }

    private fun writeJson(file: File, value: Any) {
        file.parentFile?.mkdirs()
        file.writeText(prettyGson.toJson(value) + "\n", Charsets.UTF_8)
    }
}
