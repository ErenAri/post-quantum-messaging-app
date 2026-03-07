package com.pqmsg.demo

import android.content.Context
import android.text.format.DateUtils
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.TextView

class ConversationSummaryAdapter(
    context: Context,
) : BaseAdapter() {
    private val inflater = LayoutInflater.from(context)
    private val items = mutableListOf<ConversationSummary>()

    fun submitList(next: List<ConversationSummary>) {
        items.clear()
        items.addAll(next)
        notifyDataSetChanged()
    }

    override fun getCount(): Int = items.size

    override fun getItem(position: Int): ConversationSummary = items[position]

    override fun getItemId(position: Int): Long = position.toLong()

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        val view = convertView ?: inflater.inflate(R.layout.item_conversation, parent, false)
        val item = getItem(position)

        val peerText = view.findViewById<TextView>(R.id.textConversationPeer)
        val previewText = view.findViewById<TextView>(R.id.textConversationPreview)
        val metaText = view.findViewById<TextView>(R.id.textConversationMeta)
        val unreadText = view.findViewById<TextView>(R.id.textConversationUnread)

        peerText.text = item.peerUserId
        previewText.text = item.lastPreview
        metaText.text = buildMeta(item)
        if (item.unreadCount > 0) {
            unreadText.visibility = View.VISIBLE
            unreadText.text = item.unreadCount.toString()
        } else {
            unreadText.visibility = View.GONE
            unreadText.text = ""
        }
        return view
    }

    private fun buildMeta(item: ConversationSummary): String {
        val freshness = if (item.updatedAtMillis > 0L) {
            DateUtils.getRelativeTimeSpanString(
                item.updatedAtMillis,
                System.currentTimeMillis(),
                DateUtils.MINUTE_IN_MILLIS,
            ).toString()
        } else {
            "ready to start"
        }
        return if (item.unreadCount > 0) {
            "$freshness • ${item.unreadCount} unread"
        } else {
            freshness
        }
    }
}
