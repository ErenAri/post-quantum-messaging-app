package com.pqmsg.demo

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Base64
import androidx.appcompat.app.AlertDialog
import androidx.core.content.FileProvider
import java.io.File
import java.text.DateFormat
import java.util.Date

private enum class ThreadSharedMediaFilter(val title: String) {
    ALL("All"),
    MEDIA("Media"),
    FILES("Files"),
    AUDIO("Audio"),
    ;

    fun matches(item: ThreadSharedMediaItem): Boolean =
        when (this) {
            ALL -> true
            MEDIA -> item.mimeType.startsWith("image/") || item.mimeType.startsWith("video/")
            FILES -> !item.mimeType.startsWith("image/") &&
                !item.mimeType.startsWith("video/") &&
                !item.mimeType.startsWith("audio/")
            AUDIO -> item.mimeType.startsWith("audio/")
        }
}

data class ThreadSharedMediaItem(
    val message: ThreadMessage,
    val fileName: String,
    val mimeType: String,
    val noteText: String,
    val dataBase64: String,
    val byteLength: Int,
)

object ThreadSharedMediaBrowser {
    fun show(
        context: Context,
        title: String,
        messages: List<ThreadMessage>,
        emptyMessage: String,
        onError: (Throwable) -> Unit,
    ) {
        val items = messages.mapNotNull(::toSharedMediaItem).sortedByDescending { it.message.sentAtMillis }
        if (items.isEmpty()) {
            AlertDialog.Builder(context)
                .setTitle(title)
                .setMessage(emptyMessage)
                .setPositiveButton(android.R.string.ok, null)
                .show()
            return
        }
        val filterSets = ThreadSharedMediaFilter.values()
            .map { filter -> filter to items.filter { filter.matches(it) } }
            .filter { (_, matching) -> matching.isNotEmpty() }
        AlertDialog.Builder(context)
            .setTitle(title)
            .setItems(filterSets.map { "${it.first.title} (${it.second.size})" }.toTypedArray()) { _, which ->
                showFilteredList(
                    context = context,
                    title = title,
                    filter = filterSets[which].first,
                    items = filterSets[which].second,
                    onError = onError,
                )
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showFilteredList(
        context: Context,
        title: String,
        filter: ThreadSharedMediaFilter,
        items: List<ThreadSharedMediaItem>,
        onError: (Throwable) -> Unit,
    ) {
        AlertDialog.Builder(context)
            .setTitle("$title | ${filter.title}")
            .setItems(items.map(::listLabel).toTypedArray()) { _, which ->
                showItemActions(context, items[which], onError)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showItemActions(
        context: Context,
        item: ThreadSharedMediaItem,
        onError: (Throwable) -> Unit,
    ) {
        val timestamp = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
            .format(Date(item.message.sentAtMillis))
        val details = buildString {
            append("${describeKind(item.mimeType)}\n")
            append("Sent $timestamp\n")
            append(formatByteLength(item.byteLength))
            if (item.noteText.isNotBlank()) {
                append("\n\n")
                append(item.noteText)
            }
        }
        AlertDialog.Builder(context)
            .setTitle(item.fileName)
            .setMessage(details)
            .setPositiveButton(R.string.button_open) { _, _ ->
                runCatching { openItem(context, item) }.onFailure(onError)
            }
            .setNeutralButton(R.string.thread_action_share) { _, _ ->
                runCatching { shareItem(context, item) }.onFailure(onError)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun openItem(context: Context, item: ThreadSharedMediaItem) {
        val uri = writeAttachmentToCache(context, item)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, item.mimeType)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            clipData = ClipData.newRawUri(item.fileName, uri)
        }
        context.startActivity(intent)
    }

    private fun shareItem(context: Context, item: ThreadSharedMediaItem) {
        val uri = writeAttachmentToCache(context, item)
        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = item.mimeType
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_TEXT, item.noteText.ifBlank { item.fileName })
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            clipData = ClipData.newRawUri(item.fileName, uri)
        }
        context.startActivity(
            Intent.createChooser(
                shareIntent,
                context.getString(R.string.thread_shared_media_share_chooser_title),
            ),
        )
    }

    private fun writeAttachmentToCache(context: Context, item: ThreadSharedMediaItem): Uri {
        val file = File(File(context.cacheDir, "shared_media").apply { mkdirs() }, safeFileName(item.fileName))
        file.writeBytes(Base64.decode(item.dataBase64, Base64.DEFAULT))
        return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    }

    private fun listLabel(item: ThreadSharedMediaItem): String {
        val time = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(item.message.sentAtMillis))
        val subtitle = listOf(describeKind(item.mimeType), formatByteLength(item.byteLength), time).joinToString(" | ")
        return buildString {
            append(item.fileName)
            append("\n")
            append(subtitle)
            if (item.noteText.isNotBlank()) {
                append("\n")
                append(item.noteText.take(72))
            }
        }
    }

    private fun describeKind(mimeType: String): String =
        when {
            mimeType.startsWith("image/") -> "Photo"
            mimeType.startsWith("video/") -> "Video"
            mimeType.startsWith("audio/") -> "Audio"
            mimeType == "application/pdf" -> "PDF"
            mimeType.startsWith("text/") -> "Document"
            else -> "File"
        }

    private fun formatByteLength(byteLength: Int): String =
        when {
            byteLength >= 1024 * 1024 -> String.format("%.1f MB", byteLength / (1024f * 1024f))
            byteLength >= 1024 -> String.format("%.1f KB", byteLength / 1024f)
            else -> "$byteLength B"
        }

    private fun safeFileName(fileName: String): String =
        fileName.replace(Regex("[^A-Za-z0-9._ -]"), "_").ifBlank { "attachment.bin" }

    private fun toSharedMediaItem(message: ThreadMessage): ThreadSharedMediaItem? {
        val fileName = message.attachmentFileName?.trim()
        val mimeType = message.attachmentMimeType?.trim()
        val dataBase64 = message.attachmentDataBase64?.trim()
        val byteLength = message.attachmentByteLength
        if (fileName.isNullOrBlank() || mimeType.isNullOrBlank() || dataBase64.isNullOrBlank() || byteLength == null) {
            return null
        }
        return ThreadSharedMediaItem(
            message = message,
            fileName = fileName,
            mimeType = mimeType,
            noteText = message.attachmentNoteText.orEmpty(),
            dataBase64 = dataBase64,
            byteLength = byteLength,
        )
    }
}
