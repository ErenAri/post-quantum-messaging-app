package com.pqmsg.demo

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import uniffi.pqmsg_android.activeCryptoProfile

class SecurityInfoActivity : AppCompatActivity() {
    private lateinit var store: LocalStateStore
    private lateinit var serverInput: EditText
    private lateinit var userInput: EditText
    private lateinit var refreshButton: Button
    private lateinit var backButton: Button
    private lateinit var profileText: TextView
    private lateinit var transportText: TextView
    private lateinit var pinsText: TextView
    private lateinit var localStateText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_security_info)
        store = LocalStateStore(this)

        serverInput = findViewById(R.id.editSecurityServer)
        userInput = findViewById(R.id.editSecurityUser)
        refreshButton = findViewById(R.id.buttonRefreshSecurityInfo)
        backButton = findViewById(R.id.buttonBackConversationsFromSecurity)
        profileText = findViewById(R.id.textSecurityProfile)
        transportText = findViewById(R.id.textSecurityTransport)
        pinsText = findViewById(R.id.textSecurityPins)
        localStateText = findViewById(R.id.textSecurityLocalState)

        val setup = store.loadSetup()
        serverInput.setText(intent.getStringExtra("server") ?: setup.serverUrl)
        userInput.setText(intent.getStringExtra("user") ?: setup.userId)

        serverInput.doAfterTextChanged { renderSecurityInfo() }
        userInput.doAfterTextChanged { renderSecurityInfo() }
        refreshButton.setOnClickListener { renderSecurityInfo() }
        backButton.setOnClickListener { finish() }

        renderSecurityInfo()
    }

    private fun renderSecurityInfo() {
        val server = serverInput.text.toString().trim()
        val user = userInput.text.toString().trim()

        val cryptoProfile = runCatching { activeCryptoProfile() }
            .getOrElse { "Unavailable: ${it.message ?: "native runtime error"}" }
        profileText.text = "Active Crypto Profile\n$cryptoProfile"

        val transportPolicy = runCatching {
            val policy = ApiClientFactory.resolveTransportPolicy(
                base = server,
                allowCleartextDemo = BuildConfig.ALLOW_CLEARTEXT_DEMO,
                tlsPinSha256 = BuildConfig.TLS_PIN_SHA256,
            )
            val pinLine = if (policy.certificatePin.isNullOrBlank()) {
                "TLS pin: none"
            } else {
                "TLS pin: ${policy.certificatePin}"
            }
            "Resolved base URL: ${policy.baseUrl}\n$pinLine"
        }.getOrElse {
            "Invalid transport policy: ${it.message ?: "unavailable"}"
        }
        transportText.text = "Transport Security\n$transportPolicy"

        val pinLines = store.listIdentityPins(user)
            .map {
                "${it.peerUserId}: ${it.pin.fingerprintSha256} (v${it.pin.identityKeyVersion})"
            }
        pinsText.text = if (pinLines.isEmpty()) {
            "Pinned Identities\nNo pins recorded for user '$user'"
        } else {
            "Pinned Identities\n${pinLines.joinToString("\n")}"
        }

        val sessionCount = store.countSessions(user)
        val conversations = store.listConversations(user)
        localStateText.text =
            "Local Security State\nSessions: $sessionCount\nConversations: ${conversations.size}\nCurrent user: $user"
    }
}
