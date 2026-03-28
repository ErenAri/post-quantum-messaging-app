package com.pqmsg.demo

private fun threadAttachmentKindLabel(mimeType: String): String = when {
    mimeType.startsWith("image/") -> "Photo"
    mimeType.startsWith("video/") -> "Video"
    mimeType.startsWith("audio/") -> "Audio"
    mimeType == "application/pdf" -> "PDF"
    else -> "Document"
}

private fun threadAttachmentSizeLabel(byteLength: Int?): String? {
    val bytes = byteLength ?: return null
    return when {
        bytes >= 1024 * 1024 -> String.format("%.1f MB", bytes / (1024f * 1024f))
        bytes >= 1024 -> String.format("%.1f KB", bytes / 1024f)
        else -> "$bytes B"
    }
}

private fun threadAttachmentMetadataText(message: ThreadMessage): String? {
    val fileName = message.attachmentFileName?.trim().orEmpty()
    val mimeType = message.attachmentMimeType?.trim().orEmpty()
    if (fileName.isBlank() && mimeType.isBlank()) {
        return null
    }
    val kind = threadAttachmentKindLabel(mimeType.ifBlank { "application/octet-stream" })
    val size = threadAttachmentSizeLabel(message.attachmentByteLength)
    return buildString {
        append(kind)
        if (fileName.isNotBlank()) {
            append(": ")
            append(fileName)
        }
        if (!size.isNullOrBlank()) {
            append(" (")
            append(size)
            append(")")
        }
    }
}

fun threadMessageTranscript(message: ThreadMessage): String {
    val parts = linkedSetOf<String>()
    val body = message.body.trim()
    if (body.isNotBlank()) {
        parts += body
    }
    threadAttachmentMetadataText(message)?.let { parts += it }
    val noteText = message.attachmentNoteText?.trim().orEmpty()
    if (noteText.isNotBlank() && !body.contains(noteText, ignoreCase = true)) {
        parts += noteText
    }
    return parts.joinToString("\n").trim()
}

fun threadMessageSearchText(message: ThreadMessage): String {
    val parts = linkedSetOf<String>()
    val transcript = threadMessageTranscript(message)
    if (transcript.isNotBlank()) {
        parts += transcript
    }
    message.attachmentFileName?.trim()?.takeIf { it.isNotBlank() }?.let { parts += it }
    message.attachmentMimeType?.trim()?.takeIf { it.isNotBlank() }?.let { parts += it }
    threadAttachmentMetadataText(message)?.let { parts += it }
    return parts.joinToString("\n")
}
