package com.pqmsg.demo

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import uniffi.pqmsg_android.Suite
import uniffi.pqmsg_android.activeCryptoProfile
import uniffi.pqmsg_android.buildInboxAuthHeaders
import uniffi.pqmsg_android.buildPrekeysAuthHeaders
import uniffi.pqmsg_android.buildPublishPrekeysPayload
import uniffi.pqmsg_android.buildPushTokenAuthHeaders
import uniffi.pqmsg_android.buildRegisterPayload
import uniffi.pqmsg_android.generateIdentityKeys
import uniffi.pqmsg_android.loadUserProfile

class MainActivity : AppCompatActivity() {
    private lateinit var store: LocalStateStore
    private lateinit var serverInput: EditText
    private lateinit var userInput: EditText
    private lateinit var deviceInput: EditText
    private lateinit var suiteInput: EditText
    private lateinit var peerInput: EditText
    private lateinit var pushTokenInput: EditText
    private lateinit var presetAliceButton: Button
    private lateinit var presetBobButton: Button
    private lateinit var generateButton: Button
    private lateinit var registerButton: Button
    private lateinit var publishButton: Button
    private lateinit var verifyButton: Button
    private lateinit var openChatButton: Button
    private lateinit var statusText: TextView
    private lateinit var cryptoProfileText: TextView
    private lateinit var stepKeysText: TextView
    private lateinit var stepRegisterText: TextView
    private lateinit var stepPublishText: TextView
    private lateinit var stepVerifyText: TextView
    private lateinit var errorSummaryText: TextView
    private lateinit var errorDetailsText: TextView
    private lateinit var errorToggleButton: Button
    private var errorExpanded = false
    private var progressUserId = ""
    private var progress = SetupProgress()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup)
        store = LocalStateStore(this)
        serverInput = findViewById(R.id.editServer)
        userInput = findViewById(R.id.editUser)
        deviceInput = findViewById(R.id.editDevice)
        suiteInput = findViewById(R.id.editSuite)
        peerInput = findViewById(R.id.editPeer)
        pushTokenInput = findViewById(R.id.editPushToken)
        presetAliceButton = findViewById(R.id.buttonPresetAlice)
        presetBobButton = findViewById(R.id.buttonPresetBob)
        generateButton = findViewById(R.id.buttonGenerate)
        registerButton = findViewById(R.id.buttonRegister)
        publishButton = findViewById(R.id.buttonPublish)
        verifyButton = findViewById(R.id.buttonVerifyServer)
        openChatButton = findViewById(R.id.buttonOpenChat)
        statusText = findViewById(R.id.textStatusSetup)
        cryptoProfileText = findViewById(R.id.textCryptoProfile)
        stepKeysText = findViewById(R.id.textStepKeys)
        stepRegisterText = findViewById(R.id.textStepRegister)
        stepPublishText = findViewById(R.id.textStepPublish)
        stepVerifyText = findViewById(R.id.textStepVerify)
        errorSummaryText = findViewById(R.id.textErrorSummarySetup)
        errorDetailsText = findViewById(R.id.textErrorDetailsSetup)
        errorToggleButton = findViewById(R.id.buttonToggleErrorDetailsSetup)

        val setup = store.loadSetup()
        serverInput.setText(setup.serverUrl)
        userInput.setText(setup.userId)
        deviceInput.setText(setup.deviceId)
        suiteInput.setText(setup.suiteLabel)
        peerInput.setText(setup.peerUserId)
        progressUserId = setup.userId
        progress = store.loadProgress(progressUserId)

        configureInputObservers()
        configureErrorToggle()

        presetAliceButton.setOnClickListener {
            applyPreset("alice", "bob")
        }

        presetBobButton.setOnClickListener {
            applyPreset("bob", "alice")
        }

        generateButton.setOnClickListener {
            lifecycleScope.launch {
                runAction("Generate identity keys") {
                    val user = userInput.text.toString().trim()
                    require(user.isNotBlank()) { "user id is empty" }
                    val device = normalizedDeviceId(user, deviceInput.text.toString().trim())
                    val suite = parseSuite(suiteInput.text.toString())
                    val keysJson = generateIdentityKeys(user, device, suite, 16u)
                    store.writeKeys(user, keysJson)
                    saveSetup()
                    val profile = loadUserProfile(keysJson)
                    syncProgressUser()
                    progress = progress.afterKeysGenerated()
                    store.saveProgress(progressUserId, progress)
                    "Generated keys for ${profile.userId} (${profile.deviceId})"
                }
            }
        }

        registerButton.setOnClickListener {
            lifecycleScope.launch {
                runAction("Register user") {
                    val user = userInput.text.toString().trim()
                    require(user.isNotBlank()) { "user id is empty" }
                    val keysJson = requireKeys(user)
                    val payload = buildRegisterPayload(keysJson)
                    val api = ApiClientFactory.create(serverInput.text.toString())
                    api.registerUser(
                        RegisterUserRequest(
                            user_id = payload.userId,
                            identity_x25519_pub = payload.identityX25519Pub,
                            identity_sig_pub = payload.identitySigPub,
                            device_id = payload.deviceId,
                        )
                    )
                    saveSetup()
                    syncProgressUser()
                    progress = progress.afterUserRegistered()
                    store.saveProgress(progressUserId, progress)
                    "Registered ${payload.userId}"
                }
            }
        }

        publishButton.setOnClickListener {
            lifecycleScope.launch {
                runAction("Publish prekeys") {
                    val user = userInput.text.toString().trim()
                    require(user.isNotBlank()) { "user id is empty" }
                    val keysJson = requireKeys(user)
                    val payload = buildPublishPrekeysPayload(keysJson)
                    val api = ApiClientFactory.create(serverInput.text.toString())
                    val auth = buildPrekeysAuthHeaders(keysJson, user)
                    api.publishPrekeys(
                        user,
                        auth.toHeaderMap(),
                        PublishPrekeysRequest(
                            signed_prekey_x25519_pub = payload.signedPrekeyX25519Pub,
                            sig_over_spk = payload.sigOverSpk,
                            pq_signed_prekey_pub_mlkem768 = payload.pqSignedPrekeyPubMlkem768,
                            sig_over_pqspk = payload.sigOverPqspk,
                            one_time_prekeys_x25519 = payload.oneTimePrekeysX25519,
                            one_time_prekeys_mlkem768 = payload.oneTimePrekeysMlkem768,
                        )
                    )
                    saveSetup()
                    syncProgressUser()
                    progress = progress.afterPrekeysPublished()
                    store.saveProgress(progressUserId, progress)
                    "Published prekeys for $user"
                }
            }
        }

        verifyButton.setOnClickListener {
            lifecycleScope.launch {
                runAction("Verify server") {
                    val user = userInput.text.toString().trim()
                    require(user.isNotBlank()) { "user id is empty" }
                    val keysJson = requireKeys(user)
                    val api = ApiClientFactory.create(serverInput.text.toString())
                    val ping = api.pingRoot()
                    if (!ping.isSuccessful && ping.code() >= 500) {
                        error("server ping failed with status ${ping.code()}")
                    }
                    val inboxAuth = buildInboxAuthHeaders(
                        keysJson = keysJson,
                        userId = user,
                        since = store.readCursor(user),
                    )
                    api.inbox(user, inboxAuth.toHeaderMap(), store.readCursor(user))
                    val pushToken = pushTokenInput.text.toString().trim()
                    if (pushToken.isNotEmpty()) {
                        val pushAuth = buildPushTokenAuthHeaders(
                            keysJson = keysJson,
                            userId = user,
                            fcmToken = pushToken,
                        )
                        api.registerPushToken(
                            userId = user,
                            headers = pushAuth.toHeaderMap(),
                            request = RegisterPushTokenRequest(
                                device_id = loadUserProfile(keysJson).deviceId,
                                fcm_token = pushToken,
                            ),
                        )
                    }
                    saveSetup()
                    syncProgressUser()
                    progress = progress.afterServerVerified()
                    store.saveProgress(progressUserId, progress)
                    if (pushToken.isEmpty()) {
                        "Server reachable and API authenticated for $user"
                    } else {
                        "Server reachable, API authenticated, and push token registered for $user"
                    }
                }
            }
        }

        openChatButton.setOnClickListener {
            saveSetup()
            syncProgressUser()
            val peer = peerInput.text.toString().trim()
            if (!progress.canOpenChat()) {
                statusText.text = "Complete setup steps 1-4 before opening chat."
                return@setOnClickListener
            }
            val intent = Intent(this, ConversationsActivity::class.java).apply {
                putExtra("server", serverInput.text.toString().trim())
                putExtra("user", userInput.text.toString().trim())
                putExtra("peer_seed", peer)
            }
            startActivity(intent)
        }

        lifecycleScope.launch {
            runCatching {
                activeCryptoProfile()
            }.onSuccess {
                cryptoProfileText.text = "Crypto profile: $it"
            }.onFailure {
                cryptoProfileText.text = "Crypto profile unavailable"
                renderError(UiErrorMapper.fromThrowable(it, "Native runtime check"))
            }
        }

        refreshStepUi()
    }

    private fun saveSetup() {
        val user = userInput.text.toString().trim()
        val device = normalizedDeviceId(user, deviceInput.text.toString().trim())
        store.saveSetup(
            SetupConfig(
                serverUrl = serverInput.text.toString().trim(),
                userId = user,
                deviceId = device,
                suiteLabel = suiteInput.text.toString().trim(),
                peerUserId = peerInput.text.toString().trim(),
            )
        )
    }

    private fun configureInputObservers() {
        userInput.doAfterTextChanged {
            syncProgressUser()
            refreshStepUi()
        }
        peerInput.doAfterTextChanged {
            refreshStepUi()
        }
        suiteInput.doAfterTextChanged {
            refreshStepUi()
        }
        serverInput.doAfterTextChanged {
            refreshStepUi()
        }
        deviceInput.doAfterTextChanged {
            refreshStepUi()
        }
    }

    private fun configureErrorToggle() {
        errorToggleButton.setOnClickListener {
            errorExpanded = !errorExpanded
            refreshErrorDetailsVisibility()
        }
        renderError(null)
    }

    private suspend fun runAction(action: String, block: suspend () -> String) {
        runCatching {
            block()
        }.onSuccess {
            renderError(null)
            statusText.text = it
        }.onFailure {
            renderError(UiErrorMapper.fromThrowable(it, action))
            statusText.text = "${action} failed"
        }
        refreshStepUi()
    }

    private fun applyPreset(userId: String, peerId: String) {
        userInput.setText(userId)
        peerInput.setText(peerId)
        if (deviceInput.text.toString().trim().isBlank()) {
            deviceInput.setText("${userId}-android-1")
        }
        syncProgressUser()
        saveSetup()
        refreshStepUi()
    }

    private fun syncProgressUser() {
        val currentUser = userInput.text.toString().trim()
        if (currentUser == progressUserId) {
            return
        }
        progressUserId = currentUser
        progress = store.loadProgress(progressUserId)
    }

    private fun refreshStepUi() {
        syncProgressUser()
        stepKeysText.text = stepLabel("1) Generate keys", progress.keysGenerated)
        stepRegisterText.text = stepLabel("2) Register user", progress.userRegistered)
        stepPublishText.text = stepLabel("3) Publish prekeys", progress.prekeysPublished)
        stepVerifyText.text = stepLabel("4) Verify server", progress.serverVerified)
        registerButton.isEnabled = progress.canRegister()
        publishButton.isEnabled = progress.canPublishPrekeys()
        verifyButton.isEnabled = progress.canVerifyServer()
        openChatButton.isEnabled = progress.canOpenChat()
    }

    private fun stepLabel(title: String, complete: Boolean): String {
        return if (complete) {
            "$title: done"
        } else {
            "$title: pending"
        }
    }

    private fun renderError(error: UiError?) {
        if (error == null) {
            errorSummaryText.text = ""
            errorDetailsText.text = ""
            errorSummaryText.visibility = View.GONE
            errorDetailsText.visibility = View.GONE
            errorToggleButton.visibility = View.GONE
            errorExpanded = false
            return
        }
        errorSummaryText.text = "${error.headline}\n${error.actionHint}"
        errorDetailsText.text = error.technicalDetails
        errorSummaryText.visibility = View.VISIBLE
        errorToggleButton.visibility = View.VISIBLE
        errorExpanded = false
        refreshErrorDetailsVisibility()
    }

    private fun refreshErrorDetailsVisibility() {
        if (errorExpanded) {
            errorDetailsText.visibility = View.VISIBLE
            errorToggleButton.text = "Hide technical details"
        } else {
            errorDetailsText.visibility = View.GONE
            errorToggleButton.text = "Show technical details"
        }
    }

    private fun requireKeys(user: String): String {
        return store.readKeys(user) ?: throw IllegalStateException("missing keys for user '$user'")
    }

    private fun parseSuite(value: String): Suite {
        return if (value.equals("kyber768", ignoreCase = true)) {
            Suite.KYBER768
        } else {
            Suite.ML_KEM768
        }
    }

    private fun normalizedDeviceId(user: String, device: String): String {
        return if (device.isNotBlank()) {
            device
        } else {
            "${user}-android-1"
        }
    }

}
