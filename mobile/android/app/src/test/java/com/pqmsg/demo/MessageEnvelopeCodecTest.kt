package com.pqmsg.demo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Base64

class MessageEnvelopeCodecTest {
    @Test
    fun media_envelope_round_trip() {
        val payload = Base64.getEncoder().encodeToString("binary".toByteArray())
        val encoded = MessageEnvelopeCodec.encodeMediaEnvelope(
            fileName = "report.pdf",
            mimeType = "application/pdf",
            noteText = "intel",
            dataBase64 = payload,
        )
        val decoded = MessageEnvelopeCodec.decodeMediaEnvelope(encoded)
        assertNotNull(decoded)
        decoded ?: return
        assertEquals("report.pdf", decoded.fileName)
        assertEquals("application/pdf", decoded.mimeType)
        assertEquals("intel", decoded.noteText)
        assertEquals(payload, decoded.dataBase64)
        assertEquals(6, decoded.byteLength)
    }

    @Test
    fun non_media_payload_returns_null() {
        assertNull(MessageEnvelopeCodec.decodeMediaEnvelope("hello"))
    }
}
