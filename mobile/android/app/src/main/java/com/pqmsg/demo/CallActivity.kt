package com.pqmsg.demo

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.Chronometer
import android.widget.TextView
import android.os.SystemClock
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.Base64

/**
 * Voice/video call screen using the server-side call signaling API.
 *
 * Intent extras:
 * - "peer" : String — peer user ID
 * - "call_type" : String — "audio" or "video"
 * - "call_id" : String? — non-null for incoming calls
 * - "sdp_offer_base64" : String? — non-null for incoming calls
 */
class CallActivity : AppCompatActivity() {
    private lateinit var store: LocalStateStore
    private lateinit var callStatusText: TextView
    private lateinit var peerNameText: TextView
    private lateinit var pqBadgeText: TextView
    private lateinit var callTimer: Chronometer
    private lateinit var muteButton: Button
    private lateinit var hangupButton: Button
    private lateinit var declineButton: Button
    private lateinit var acceptButton: Button

    private var peerUserId = ""
    private var callType = "audio"
    private var callId: String? = null
    private var sdpOfferBase64: String? = null
    private var isMuted = false
    private var signalPollJob: Job? = null
    private var callState = "idle"

    companion object {
        private const val PERMISSION_REQUEST_CODE = 2001
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = LocalStateStore(this)
        peerUserId = intent.getStringExtra("peer") ?: ""
        callType = intent.getStringExtra("call_type") ?: "audio"
        callId = intent.getStringExtra("call_id")
        sdpOfferBase64 = intent.getStringExtra("sdp_offer_base64")

        if (peerUserId.isBlank()) {
            finish()
            return
        }

        buildUi()
        checkPermissionsAndStart()
    }

    override fun onDestroy() {
        super.onDestroy()
        signalPollJob?.cancel()
    }

    private fun buildUi() {
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
            gravity = android.view.Gravity.CENTER_HORIZONTAL
            setBackgroundColor(0xFF1A2332.toInt())
        }

        peerNameText = TextView(this).apply {
            text = peerUserId
            textSize = 24f
            setTextColor(0xFFFFFFFF.toInt())
            gravity = android.view.Gravity.CENTER
            setPadding(0, 32, 0, 8)
        }
        layout.addView(peerNameText)

        callStatusText = TextView(this).apply {
            text = if (callId != null) "Incoming $callType call…" else "Calling…"
            textSize = 16f
            setTextColor(0xAAFFFFFF.toInt())
            gravity = android.view.Gravity.CENTER
            setPadding(0, 0, 0, 16)
        }
        layout.addView(callStatusText)

        callTimer = Chronometer(this).apply {
            textSize = 14f
            setTextColor(0x88FFFFFF.toInt())
            gravity = android.view.Gravity.CENTER
            visibility = View.GONE
        }
        layout.addView(callTimer)

        pqBadgeText = TextView(this).apply {
            text = "🛡️ PQ E2E Encrypted"
            textSize = 12f
            setTextColor(0xFF4ADE80.toInt())
            gravity = android.view.Gravity.CENTER
            setPadding(0, 16, 0, 32)
            visibility = View.GONE
        }
        layout.addView(pqBadgeText)

        val controlsLayout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER
            setPadding(0, 48, 0, 0)
        }

        // Incoming call: accept/decline buttons
        if (callId != null) {
            declineButton = Button(this).apply {
                text = "✖ Decline"
                setTextColor(0xFFFFFFFF.toInt())
                setBackgroundColor(0xFFE53E3E.toInt())
                setOnClickListener { handleDecline() }
            }
            controlsLayout.addView(declineButton, android.widget.LinearLayout.LayoutParams(0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(8, 0, 8, 0) })

            acceptButton = Button(this).apply {
                text = "✓ Accept"
                setTextColor(0xFFFFFFFF.toInt())
                setBackgroundColor(0xFF38A169.toInt())
                setOnClickListener { handleAccept() }
            }
            controlsLayout.addView(acceptButton, android.widget.LinearLayout.LayoutParams(0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(8, 0, 8, 0) })
        }

        muteButton = Button(this).apply {
            text = "🎤 Mute"
            setOnClickListener { toggleMute() }
            visibility = if (callId != null) View.GONE else View.VISIBLE
        }
        controlsLayout.addView(muteButton, android.widget.LinearLayout.LayoutParams(0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(8, 0, 8, 0) })

        hangupButton = Button(this).apply {
            text = "📞 Hang Up"
            setTextColor(0xFFFFFFFF.toInt())
            setBackgroundColor(0xFFE53E3E.toInt())
            setOnClickListener { handleHangup() }
            visibility = if (callId != null) View.GONE else View.VISIBLE
        }
        controlsLayout.addView(hangupButton, android.widget.LinearLayout.LayoutParams(0, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(8, 0, 8, 0) })

        layout.addView(controlsLayout)
        setContentView(layout)
    }

    private fun checkPermissionsAndStart() {
        val perms = mutableListOf(Manifest.permission.RECORD_AUDIO)
        if (callType == "video") {
            perms.add(Manifest.permission.CAMERA)
        }
        val needed = perms.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (needed.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, needed.toTypedArray(), PERMISSION_REQUEST_CODE)
        } else {
            onPermissionsGranted()
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                onPermissionsGranted()
            } else {
                callStatusText.text = "Permissions required for calling"
                hangupButton.visibility = View.VISIBLE
            }
        }
    }

    private fun onPermissionsGranted() {
        if (callId != null) {
            // Incoming call — wait for user to accept
            callState = "incoming-ringing"
        } else {
            // Outgoing call — start immediately
            startOutgoingCall()
        }
    }

    private fun startOutgoingCall() {
        callState = "outgoing-ringing"
        callStatusText.text = "Ringing…"

        lifecycleScope.launch {
            try {
                val setup = store.loadSetup()
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                    deviceId = setup.deviceId,
                    pushToken = "",
                )

                // Create SDP offer placeholder (real WebRTC SDP would come from
                // org.webrtc.PeerConnection — using placeholder for signaling demo)
                val sdpOffer = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n"
                val sdpOfferB64 = Base64.getEncoder().encodeToString(sdpOffer.toByteArray())

                val authMessage = "call-offer:${setup.userId}:${setup.deviceId}:$peerUserId"
                val headers = buildFormatStringAuth(store, setup, authMessage)

                val response = context.api.callOffer(
                    peerUserId,
                    headers,
                    CallOfferRequest(
                        caller_user_id = setup.userId,
                        device_id = setup.deviceId,
                        sdp_offer_base64 = sdpOfferB64,
                        call_type = callType,
                    ),
                )

                callId = response.call_id
                callState = "outgoing-ringing"
                callStatusText.text = "Ringing…"

                // Start polling for answer/ICE/hangup signals
                startSignalPolling(setup, context.api)

            } catch (e: Exception) {
                callStatusText.text = "Call failed: ${e.message}"
            }
        }
    }

    private fun handleAccept() {
        val cid = callId ?: return
        callState = "connecting"
        callStatusText.text = "Connecting…"

        if (::acceptButton.isInitialized) acceptButton.visibility = View.GONE
        if (::declineButton.isInitialized) declineButton.visibility = View.GONE
        muteButton.visibility = View.VISIBLE
        hangupButton.visibility = View.VISIBLE

        lifecycleScope.launch {
            try {
                val setup = store.loadSetup()
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                    deviceId = setup.deviceId,
                    pushToken = "",
                )

                val sdpAnswer = "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n"
                val sdpAnswerB64 = Base64.getEncoder().encodeToString(sdpAnswer.toByteArray())

                val authMessage = "call-answer:${setup.userId}:${setup.deviceId}:$cid"
                val headers = buildFormatStringAuth(store, setup, authMessage)

                context.api.callAnswer(
                    cid,
                    headers,
                    CallAnswerRequest(
                        callee_user_id = setup.userId,
                        device_id = setup.deviceId,
                        sdp_answer_base64 = sdpAnswerB64,
                    ),
                )

                onCallConnected()
                startSignalPolling(setup, context.api)

            } catch (e: Exception) {
                callStatusText.text = "Accept failed: ${e.message}"
            }
        }
    }

    private fun handleDecline() {
        handleHangup()
    }

    private fun handleHangup() {
        val cid = callId
        callState = "ended"
        callStatusText.text = "Call ended"
        callTimer.stop()
        signalPollJob?.cancel()

        if (cid != null) {
            lifecycleScope.launch {
                try {
                    val setup = store.loadSetup()
                    val context = MessagingCoordinator.ensureReady(
                        store = store,
                        serverUrl = setup.serverUrl,
                        userId = setup.userId,
                        suiteLabel = setup.suiteLabel,
                        deviceId = setup.deviceId,
                        pushToken = "",
                    )
                    val authMessage = "call-hangup:${setup.userId}:${setup.deviceId}:$cid"
                    val headers = buildFormatStringAuth(store, setup, authMessage)
                    context.api.callHangup(
                        cid,
                        headers,
                        CallHangupRequest(
                            user_id = setup.userId,
                            device_id = setup.deviceId,
                            reason = "user-hangup",
                        ),
                    )
                } catch (_: Exception) {
                    // Best-effort hangup
                }
            }
        }

        // Return to previous screen after short delay
        muteButton.postDelayed({ finish() }, 1500)
    }

    private fun toggleMute() {
        isMuted = !isMuted
        muteButton.text = if (isMuted) "🔇 Unmute" else "🎤 Mute"
    }

    private fun onCallConnected() {
        callState = "active"
        callStatusText.text = "Connected"
        pqBadgeText.visibility = View.VISIBLE
        callTimer.base = SystemClock.elapsedRealtime()
        callTimer.visibility = View.VISIBLE
        callTimer.start()
    }

    private fun startSignalPolling(setup: SetupConfig, api: PqmsgApi) {
        var lastSignalId = 0L
        signalPollJob = lifecycleScope.launch {
            while (isActive && callState != "ended") {
                delay(1000)
                val cid = callId ?: continue
                try {
                    val authMessage = "call-poll:${setup.userId}:${setup.deviceId}:$cid"
                    val headers = buildFormatStringAuth(store, setup, authMessage)
                    val response = api.pollCallSignals(cid, headers, lastSignalId)

                    for (signal in response.signals) {
                        when (signal.signal_type) {
                            "answer" -> {
                                onCallConnected()
                            }
                            "hangup" -> {
                                callState = "ended"
                                callStatusText.text = "Call ended by peer"
                                callTimer.stop()
                                signalPollJob?.cancel()
                                muteButton.postDelayed({ finish() }, 1500)
                            }
                            "ice-candidate" -> {
                                // In a full implementation, add ICE candidate to PeerConnection
                            }
                        }
                    }
                } catch (_: Exception) {
                    // Polling failure — retry on next interval
                }
            }
        }
    }

    private fun buildFormatStringAuth(
        store: LocalStateStore,
        setup: SetupConfig,
        message: String,
    ): Map<String, String> {
        val keysJson = store.readKeysJson(setup.userId)
            ?: throw IllegalStateException("No keys available")
        val headers = uniffi.pqmsg_android.buildFormatStringAuthHeaders(keysJson, message)
        return headers.toHeaderMap()
    }
}
