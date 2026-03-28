package com.pqmsg.demo

import android.content.res.ColorStateList
import android.content.Context
import android.view.GestureDetector
import android.view.Gravity
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import java.text.DateFormat
import java.util.Date
import kotlin.math.abs
import kotlin.math.min

class ThreadMessageAdapter(
    context: Context,
    private val onSwipeReply: ((ThreadMessage) -> Unit)? = null,
    private val onOpenReplyThread: ((ThreadMessage) -> Unit)? = null,
    private val onOpenQuotedReply: ((Long) -> Unit)? = null,
) : BaseAdapter() {
    private val inflater = LayoutInflater.from(context)
    private val appContext = context.applicationContext
    private val items = mutableListOf<ThreadMessage>()
    private val replyLookup = linkedMapOf<Long, ThreadMessage>()
    private val replyCounts = linkedMapOf<Long, Int>()
    private val selectedMessageKeys = linkedSetOf<String>()
    private val searchedMessageKeys = linkedSetOf<String>()
    private var focusedReplyTargetId: Long? = null
    private var activeSearchMessageKey: String? = null
    private var selectionModeEnabled = false
    private val swipeReplyThresholdPx = context.resources.displayMetrics.density * 72f
    private val swipeReplyPreviewPx = context.resources.displayMetrics.density * 18f

    fun submitList(next: List<ThreadMessage>) {
        items.clear()
        items.addAll(next)
        replyLookup.clear()
        replyCounts.clear()
        next.forEach { message ->
            replyLookup[message.sentAtMillis] = message
            message.transportMessageId?.let { replyLookup[it] = message }
            message.replyToId?.let { replyCounts[it] = (replyCounts[it] ?: 0) + 1 }
        }
        if (focusedReplyTargetId != null && replyLookup[focusedReplyTargetId] == null) {
            focusedReplyTargetId = null
        }
        notifyDataSetChanged()
    }

    fun setSelectionState(enabled: Boolean, selectedKeys: Set<String>) {
        selectionModeEnabled = enabled
        selectedMessageKeys.clear()
        selectedMessageKeys.addAll(selectedKeys)
        notifyDataSetChanged()
    }

    fun setSearchState(searchedKeys: Set<String>, activeKey: String?) {
        searchedMessageKeys.clear()
        searchedMessageKeys.addAll(searchedKeys)
        activeSearchMessageKey = activeKey
        notifyDataSetChanged()
    }

    fun focusReplyThread(targetId: Long?) {
        if (focusedReplyTargetId == targetId) return
        focusedReplyTargetId = targetId
        notifyDataSetChanged()
    }

    fun getFocusedReplyThreadId(): Long? = focusedReplyTargetId

    override fun getCount(): Int = items.size

    override fun getItem(position: Int): ThreadMessage = items[position]

    override fun getItemId(position: Int): Long = position.toLong()

    fun messageKey(item: ThreadMessage): String {
        val stableId = item.transportMessageId ?: item.sentAtMillis
        return "${item.direction}:$stableId"
    }

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        val view = convertView ?: inflater.inflate(R.layout.item_thread_message, parent, false)
        val item = getItem(position)
        val isOutbound = item.direction == "outbound"
        val messageKey = messageKey(item)
        val isSelected = selectedMessageKeys.contains(messageKey)
        val isSearchMatch = searchedMessageKeys.contains(messageKey)
        val isActiveSearch = activeSearchMessageKey == messageKey

        val row = view.findViewById<FrameLayout>(R.id.threadMessageRow)
        val bubble = view.findViewById<LinearLayout>(R.id.threadMessageBubble)
        val body = view.findViewById<TextView>(R.id.textThreadMessageBody)
        val meta = view.findViewById<TextView>(R.id.textThreadMessageMeta)
        val reactions = view.findViewById<ChipGroup>(R.id.threadMessageReactions)
        val replyThreadChip = view.findViewById<Chip>(R.id.chipThreadReplies)
        val reply = view.findViewById<TextView>(R.id.textThreadMessageReply)

        val params = bubble.layoutParams as FrameLayout.LayoutParams
        params.gravity = if (isOutbound) Gravity.END else Gravity.START
        bubble.layoutParams = params
        row.foreground = null
        row.isActivated = isSelected
        row.isSelected = isSelected
        if (isSelected) {
            row.setBackgroundResource(R.drawable.bg_thread_message_selected)
        } else if (isActiveSearch) {
            row.setBackgroundResource(R.drawable.bg_thread_message_search_active)
        } else if (isSearchMatch) {
            row.setBackgroundResource(R.drawable.bg_thread_message_search_match)
        } else {
            row.background = null
        }
        bubble.translationX = 0f

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
        reply.setTextColor(
            if (item.replyToId != null && item.replyToId == focusedReplyTargetId) {
                body.context.getColor(R.color.pq_hero)
            } else if (isOutbound) {
                body.context.getColor(R.color.pq_hero_accent)
            } else {
                body.context.getColor(R.color.pq_ink_muted)
            },
        )
        bindReplyQuote(reply, item)

        bindReactionChips(reactions, item, isOutbound)
        bindReplyThreadChip(replyThreadChip, item)
        bindSwipeReplyGesture(bubble, item)
        return view
    }

    private fun bindSwipeReplyGesture(bubble: View, item: ThreadMessage) {
        val replyHandler = onSwipeReply
        if (replyHandler == null || selectionModeEnabled) {
            bubble.setOnTouchListener(null)
            return
        }
        var startRawX = 0f
        var startRawY = 0f
        var replyTriggered = false
        val detector = GestureDetector(
            bubble.context,
            object : GestureDetector.SimpleOnGestureListener() {
                override fun onDown(e: MotionEvent): Boolean = true

                override fun onScroll(
                    e1: MotionEvent?,
                    e2: MotionEvent,
                    distanceX: Float,
                    distanceY: Float,
                ): Boolean {
                    if (e1 == null) return false
                    val dx = e2.rawX - e1.rawX
                    val dy = e2.rawY - e1.rawY
                    if (!replyTriggered && dx > swipeReplyThresholdPx && abs(dx) > abs(dy) * 1.35f) {
                        replyTriggered = true
                        bubble.animate()
                            .translationX(0f)
                            .setDuration(120)
                            .withEndAction { replyHandler(item) }
                            .start()
                        return true
                    }
                    return false
                }
            },
        )
        bubble.setOnTouchListener { v, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    startRawX = event.rawX
                    startRawY = event.rawY
                    replyTriggered = false
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = (event.rawX - startRawX).coerceAtLeast(0f)
                    val dy = abs(event.rawY - startRawY)
                    if (!replyTriggered && dx > dy) {
                        v.translationX = min(dx * 0.18f, swipeReplyPreviewPx)
                    }
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    v.animate().translationX(0f).setDuration(120).start()
                }
            }
            detector.onTouchEvent(event)
            false
        }
    }

    private fun bindReactionChips(group: ChipGroup, item: ThreadMessage, isOutbound: Boolean) {
        val entries = item.reactions?.entries?.toList().orEmpty()
        if (entries.isEmpty()) {
            group.removeAllViews()
            group.visibility = View.GONE
            return
        }
        val context = group.context
        val backgroundColor = if (isOutbound) {
            context.getColor(R.color.pq_reaction_sent_bg)
        } else {
            context.getColor(R.color.pq_reaction_received_bg)
        }
        val textColor = if (isOutbound) {
            context.getColor(R.color.pq_reaction_sent_text)
        } else {
            context.getColor(R.color.pq_reaction_received_text)
        }
        group.removeAllViews()
        entries.forEach { (emoji, userId) ->
            val label = if (userId.equals("You", ignoreCase = true)) emoji else "$emoji $userId"
            val chip = Chip(context, null, R.style.Widget_PQMsg_Chip_Reaction).apply {
                text = label
                isClickable = false
                isCheckable = false
                setEnsureMinTouchTargetSize(false)
                chipBackgroundColor = ColorStateList.valueOf(backgroundColor)
                setTextColor(textColor)
            }
            group.addView(chip)
        }
        group.visibility = View.VISIBLE
    }

    private fun bindReplyQuote(replyView: TextView, item: ThreadMessage) {
        val targetId = item.replyToId
        if (
            selectionModeEnabled ||
            targetId == null ||
            replyView.visibility != View.VISIBLE ||
            onOpenQuotedReply == null
        ) {
            replyView.setOnClickListener(null)
            replyView.isClickable = false
            replyView.isFocusable = false
            return
        }
        replyView.isClickable = true
        replyView.isFocusable = true
        replyView.setOnClickListener { onOpenQuotedReply.invoke(targetId) }
    }

    private fun bindReplyThreadChip(chip: Chip, item: ThreadMessage) {
        val targetId = item.transportMessageId ?: item.sentAtMillis
        val count = replyCounts[targetId] ?: 0
        if (count <= 0) {
            chip.visibility = View.GONE
            chip.setOnClickListener(null)
            return
        }
        val isFocused = focusedReplyTargetId == targetId
        val backgroundColor = if (isFocused) {
            chip.context.getColor(R.color.pq_reply_chip_active_bg)
        } else {
            chip.context.getColor(R.color.pq_reply_chip_bg)
        }
        val textColor = if (isFocused) {
            chip.context.getColor(R.color.pq_reply_chip_active_text)
        } else {
            chip.context.getColor(R.color.pq_reply_chip_text)
        }
        chip.visibility = View.VISIBLE
        chip.text = appContext.resources.getQuantityString(R.plurals.thread_reply_count, count, count)
        chip.chipBackgroundColor = ColorStateList.valueOf(backgroundColor)
        chip.setTextColor(textColor)
        if (selectionModeEnabled) {
            chip.setOnClickListener(null)
            chip.isClickable = false
            chip.isFocusable = false
        } else {
            chip.isClickable = true
            chip.isFocusable = true
            chip.setOnClickListener { onOpenReplyThread?.invoke(item) }
        }
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
