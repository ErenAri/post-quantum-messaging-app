package com.pqmsg.demo

import android.content.Context
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import java.text.DateFormat
import java.util.Date

class ThreadMessageAdapter(
    context: Context,
) : BaseAdapter() {
    private val inflater = LayoutInflater.from(context)
    private val items = mutableListOf<ThreadMessage>()
    private val replyLookup = linkedMapOf<Long, ThreadMessage>()

    fun submitList(next: List<ThreadMessage>) {
        items.clear()
        items.addAll(next)
        replyLookup.clear()
        next.forEach { message ->
            replyLookup[message.sentAtMillis] = message
            message.transportMessageId?.let { replyLookup[it] = message }
        }
        notifyDataSetChanged()
    }

    override fun getCount(): Int = items.size

    override fun getItem(position: Int): ThreadMessage = items[position]

    override fun getItemId(position: Int): Long = position.toLong()

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        val view = convertView ?: inflater.inflate(R.layout.item_thread_message, parent, false)
        val item = getItem(position)
        val isOutbound = item.direction == "outbound"

        val row = view.findViewById<FrameLayout>(R.id.threadMessageRow)
        val bubble = view.findViewById<LinearLayout>(R.id.threadMessageBubble)
        val body = view.findViewById<TextView>(R.id.textThreadMessageBody)
        val meta = view.findViewById<TextView>(R.id.textThreadMessageMeta)
        val reactions = view.findViewById<TextView>(R.id.textThreadMessageReactions)
        val reply = view.findViewById<TextView>(R.id.textThreadMessageReply)

        val params = bubble.layoutParams as FrameLayout.LayoutParams
        params.gravity = if (isOutbound) Gravity.END else Gravity.START
        bubble.layoutParams = params
        row.foreground = null

        if (isOutbound) {
            bubble.setBackgroundResource(R.drawable.bg_bubble_sent)
            body.setTextColor(body.context.getColor(R.color.pq_bubble_sent_text))
            meta.setTextColor(body.context.getColor(R.color.pq_hero_accent))
        } else {
            bubble.setBackgroundResource(R.drawable.bg_bubble_received)
            body.setTextColor(body.context.getColor(R.color.pq_bubble_received_text))
            meta.setTextColor(body.context.getColor(R.color.pq_ink_muted))
        }

        body.text = item.body
        meta.text = buildMeta(item)

        val replyText = item.replyToId?.let { repliedId ->
            replyLookup[repliedId]?.body?.take(72) ?: "Replying to an earlier message"
        }.orEmpty()
        reply.visibility = if (replyText.isBlank()) View.GONE else View.VISIBLE
        reply.text = replyText

        val reactionsText = item.reactions
            ?.entries
            ?.joinToString("  ") { (emoji, userId) ->
                if (userId.equals("You", ignoreCase = true)) emoji else "$emoji $userId"
            }
            .orEmpty()
        reactions.visibility = if (reactionsText.isBlank()) View.GONE else View.VISIBLE
        reactions.text = reactionsText
        return view
    }

    private fun buildMeta(item: ThreadMessage): String {
        val timeLabel = DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(item.sentAtMillis))
        val receiptLabel = when (item.receiptStatus?.lowercase()) {
            "read" -> "Read"
            "delivered" -> "Delivered"
            "sent" -> "Sent"
            else -> null
        }
        return listOfNotNull(timeLabel, receiptLabel).joinToString("  ")
    }
}
