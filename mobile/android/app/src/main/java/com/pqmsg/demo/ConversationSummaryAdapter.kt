package com.pqmsg.demo

import android.content.Context
import android.text.format.DateUtils
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.TextView

enum class InboxItemKind {
    DIRECT,
    GROUP,
    REQUEST,
}

data class InboxListItem(
    val kind: InboxItemKind,
    val id: String,
    val title: String,
    val secondaryLabel: String?,
    val preview: String,
    val updatedAtMillis: Long,
    val unreadCount: Int,
)

class ConversationSummaryAdapter(
    context: Context,
) : BaseAdapter() {
    private val inflater = LayoutInflater.from(context)
    private val items = mutableListOf<InboxListItem>()

    fun submitList(next: List<InboxListItem>) {
        items.clear()
        items.addAll(next)
        notifyDataSetChanged()
    }

    override fun getCount(): Int = items.size

    override fun getItem(position: Int): InboxListItem = items[position]

    override fun getItemId(position: Int): Long = position.toLong()

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        val view = convertView ?: inflater.inflate(R.layout.item_conversation, parent, false)
        val item = getItem(position)

        view.findViewById<TextView>(R.id.textConversationPeer).text = item.title
        view.findViewById<TextView>(R.id.textConversationPreview).text = item.preview
        view.findViewById<TextView>(R.id.textConversationTime).text = buildFreshness(item.updatedAtMillis)
        view.findViewById<TextView>(R.id.textConversationAvatar).text = buildAvatarText(item.title, item.kind)

        val metaText = view.findViewById<TextView>(R.id.textConversationMeta)
        if (item.secondaryLabel.isNullOrBlank()) {
            metaText.visibility = View.GONE
            metaText.text = ""
        } else {
            metaText.visibility = View.VISIBLE
            metaText.text = item.secondaryLabel
        }

        val unreadText = view.findViewById<TextView>(R.id.textConversationUnread)
        if (item.unreadCount > 0) {
            unreadText.visibility = View.VISIBLE
            unreadText.text = item.unreadCount.toString()
        } else {
            unreadText.visibility = View.GONE
            unreadText.text = ""
        }
        return view
    }

    private fun buildFreshness(updatedAtMillis: Long): String {
        return if (updatedAtMillis > 0L) {
            DateUtils.getRelativeTimeSpanString(
                updatedAtMillis,
                System.currentTimeMillis(),
                DateUtils.MINUTE_IN_MILLIS,
            ).toString()
        } else {
            "New"
        }
    }

    private fun buildAvatarText(label: String, kind: InboxItemKind): String {
        val trimmed = label.trim()
        if (trimmed.isEmpty()) {
            return when (kind) {
                InboxItemKind.REQUEST -> "RQ"
                InboxItemKind.GROUP -> "GR"
                InboxItemKind.DIRECT -> "?"
            }
        }
        val parts = trimmed.split(" ", "-", "_", "@").filter { it.isNotBlank() }
        return when {
            parts.size >= 2 -> (parts[0].first().toString() + parts[1].first().toString()).uppercase()
            else -> trimmed.take(2).uppercase()
        }
    }
}
