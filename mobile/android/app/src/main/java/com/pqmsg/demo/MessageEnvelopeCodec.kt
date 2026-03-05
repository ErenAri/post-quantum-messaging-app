package com.pqmsg.demo

import java.nio.charset.StandardCharsets
import java.util.Base64

data class MediaEnvelope(
    val fileName: String,
    val mimeType: String,
    val noteText: String,
    val dataBase64: String,
    val byteLength: Int,
)

object MessageEnvelopeCodec {
    private const val mediaPrefix = "pqmsg-media-v1"

    fun encodeMediaEnvelope(
        fileName: String,
        mimeType: String,
        noteText: String,
        dataBase64: String,
    ): String {
        val encoder = Base64.getEncoder()
        val fileNamePart = encoder.encodeToString(fileName.toByteArray(StandardCharsets.UTF_8))
        val mimeTypePart = encoder.encodeToString(mimeType.toByteArray(StandardCharsets.UTF_8))
        val notePart = encoder.encodeToString(noteText.toByteArray(StandardCharsets.UTF_8))
        return listOf(mediaPrefix, fileNamePart, mimeTypePart, notePart, dataBase64).joinToString("|")
    }

    fun decodeMediaEnvelope(plaintext: String): MediaEnvelope? {
        val parts = plaintext.split("|", limit = 5)
        if (parts.size != 5 || parts.first() != mediaPrefix) {
            return null
        }
        val decoder = Base64.getDecoder()
        return runCatching {
            val fileName = String(decoder.decode(parts[1]), StandardCharsets.UTF_8)
            val mimeType = String(decoder.decode(parts[2]), StandardCharsets.UTF_8)
            val noteText = String(decoder.decode(parts[3]), StandardCharsets.UTF_8)
            val dataBytes = decoder.decode(parts[4])
            MediaEnvelope(
                fileName = fileName,
                mimeType = mimeType,
                noteText = noteText,
                dataBase64 = parts[4],
                byteLength = dataBytes.size,
            )
        }.getOrNull()
    }
}
