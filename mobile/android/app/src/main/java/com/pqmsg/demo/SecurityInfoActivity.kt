package com.pqmsg.demo

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Toast
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import uniffi.pqmsg_android.Suite
import uniffi.pqmsg_android.activeCryptoProfile
import uniffi.pqmsg_android.buildIdentityLogAuthHeaders
import uniffi.pqmsg_android.buildLinkDeviceAuthHeaders
import uniffi.pqmsg_android.buildListDevicesAuthHeaders
import uniffi.pqmsg_android.buildPrekeysAuthHeaders
import uniffi.pqmsg_android.buildRevokeDeviceAuthHeaders
import uniffi.pqmsg_android.buildRetireDeviceAuthHeaders
import uniffi.pqmsg_android.buildRotateConfirmAuthHeaders
import uniffi.pqmsg_android.buildRotateConfirmPayload
import uniffi.pqmsg_android.buildRotateInitAuthHeaders
import uniffi.pqmsg_android.buildRotateInitPayload
import uniffi.pqmsg_android.buildPublishPrekeysPayload
import uniffi.pqmsg_android.generateIdentityKeys
import uniffi.pqmsg_android.loadUserProfile
import uniffi.pqmsg_android.prepareSecondaryDevicePackage

class SecurityInfoActivity : AppCompatActivity() {
    private lateinit var store: LocalStateStore
    private lateinit var serverInput: EditText
    private lateinit var userInput: EditText
    private lateinit var managedDeviceInput: EditText
    private lateinit var onboardingPassphraseInput: EditText
    private lateinit var onboardingPackageInput: EditText
    private lateinit var refreshButton: Button
    private lateinit var listDevicesButton: Button
    private lateinit var linkDeviceButton: Button
    private lateinit var revokeDeviceButton: Button
    private lateinit var listIdentityLogButton: Button
    private lateinit var rotateIdentityButton: Button
    private lateinit var prepareSecondaryDeviceButton: Button
    private lateinit var copyOnboardingPackageButton: Button
    private lateinit var resetButton: Button
    private lateinit var backButton: Button
    private lateinit var statusText: TextView
    private lateinit var profileText: TextView
    private lateinit var transportText: TextView
    private lateinit var pinsText: TextView
    private lateinit var devicesText: TextView
    private lateinit var identityLogText: TextView
    private lateinit var localStateText: TextView
    private var lastDeviceSnapshot: DeviceListResponse? = null
    private var lastIdentityLogSnapshot: IdentityLogResponse? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_security_info)
        store = LocalStateStore(this)

        serverInput = findViewById(R.id.editSecurityServer)
        userInput = findViewById(R.id.editSecurityUser)
        managedDeviceInput = findViewById(R.id.editSecurityManagedDevice)
        onboardingPassphraseInput = findViewById(R.id.editSecurityOnboardingPassphrase)
        onboardingPackageInput = findViewById(R.id.editSecurityOnboardingPackage)
        refreshButton = findViewById(R.id.buttonRefreshSecurityInfo)
        listDevicesButton = findViewById(R.id.buttonListDevices)
        linkDeviceButton = findViewById(R.id.buttonLinkDevice)
        revokeDeviceButton = findViewById(R.id.buttonRevokeDevice)
        listIdentityLogButton = findViewById(R.id.buttonListIdentityLog)
        rotateIdentityButton = findViewById(R.id.buttonRotateIdentity)
        prepareSecondaryDeviceButton = findViewById(R.id.buttonPrepareSecondaryDevicePackage)
        copyOnboardingPackageButton = findViewById(R.id.buttonCopyOnboardingPackage)
        resetButton = findViewById(R.id.buttonResetLocalState)
        backButton = findViewById(R.id.buttonBackConversationsFromSecurity)
        statusText = findViewById(R.id.textSecurityStatus)
        profileText = findViewById(R.id.textSecurityProfile)
        transportText = findViewById(R.id.textSecurityTransport)
        pinsText = findViewById(R.id.textSecurityPins)
        devicesText = findViewById(R.id.textSecurityDevices)
        identityLogText = findViewById(R.id.textSecurityIdentityLog)
        localStateText = findViewById(R.id.textSecurityLocalState)

        val setup = store.loadSetup()
        serverInput.setText(intent.getStringExtra("server") ?: setup.serverUrl)
        userInput.setText(intent.getStringExtra("user") ?: setup.userId)
        managedDeviceInput.setText(defaultManagedDeviceId(userInput.text.toString().trim()))

        serverInput.doAfterTextChanged {
            lastDeviceSnapshot = null
            lastIdentityLogSnapshot = null
            renderSecurityInfo()
            syncActionAvailability()
        }
        userInput.doAfterTextChanged {
            lastDeviceSnapshot = null
            lastIdentityLogSnapshot = null
            if (managedDeviceInput.text.toString().trim().isBlank()) {
                managedDeviceInput.setText(defaultManagedDeviceId(it?.toString().orEmpty().trim()))
            }
            renderSecurityInfo()
            syncActionAvailability()
        }
        managedDeviceInput.doAfterTextChanged {
            syncActionAvailability()
        }
        onboardingPackageInput.doAfterTextChanged {
            syncActionAvailability()
        }
        refreshButton.setOnClickListener { renderSecurityInfo() }
        listDevicesButton.setOnClickListener { runSecurityAction("List devices") { listLinkedDevices() } }
        linkDeviceButton.setOnClickListener { runSecurityAction("Link device") { linkManagedDevice() } }
        revokeDeviceButton.setOnClickListener { runSecurityAction("Revoke device") { revokeManagedDevice() } }
        listIdentityLogButton.setOnClickListener {
            runSecurityAction("Load identity log") { loadIdentityLog() }
        }
        rotateIdentityButton.setOnClickListener {
            runSecurityAction("Rotate identity") { rotateIdentity() }
        }
        prepareSecondaryDeviceButton.setOnClickListener {
            runSecurityAction("Prepare secondary device") { prepareSecondaryDeviceOnboardingPackage() }
        }
        copyOnboardingPackageButton.setOnClickListener { copyOnboardingPackageToClipboard() }
        resetButton.setOnClickListener { confirmResetLocalState() }
        backButton.setOnClickListener { finish() }

        renderSecurityInfo()
        syncActionAvailability()
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
        devicesText.text = buildDeviceSnapshotText(user)
        identityLogText.text = buildIdentityLogText(user)

        val sessionCount = store.countSessions(user)
        val conversations = store.listConversations(user)
        localStateText.text =
            "Local Security State\nSessions: $sessionCount\nConversations: ${conversations.size}\nCurrent user: $user"
    }

    private fun confirmResetLocalState() {
        val user = userInput.text.toString().trim()
        if (user.isBlank()) {
            Toast.makeText(this, "Enter user id before wiping local state.", Toast.LENGTH_SHORT).show()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.reset_local_state_title)
            .setMessage(getString(R.string.reset_local_state_message, user))
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.button_reset_local_state) { _, _ ->
                lifecycleScope.launch {
                    runCatching {
                        resetLocalStateWithRemoteRetire(user)
                    }.onSuccess { message ->
                        statusText.text = message
                        Toast.makeText(this@SecurityInfoActivity, message, Toast.LENGTH_SHORT).show()
                    }.onFailure {
                        val mapped = UiErrorMapper.fromThrowable(it, "Reset local state")
                        statusText.text = mapped.headline
                        Toast.makeText(this@SecurityInfoActivity, mapped.headline, Toast.LENGTH_LONG).show()
                    }
                }
            }
            .show()
    }

    private fun syncActionAvailability() {
        val hasUser = userInput.text.toString().trim().isNotBlank()
        val hasManagedDevice = managedDeviceInput.text.toString().trim().isNotBlank()
        val hasOnboardingPackage = onboardingPackageInput.text.toString().trim().isNotBlank()
        listDevicesButton.isEnabled = hasUser
        linkDeviceButton.isEnabled = hasUser && hasManagedDevice
        revokeDeviceButton.isEnabled = hasUser && hasManagedDevice
        listIdentityLogButton.isEnabled = hasUser
        rotateIdentityButton.isEnabled = hasUser && hasManagedDevice
        prepareSecondaryDeviceButton.isEnabled = hasUser && hasManagedDevice
        copyOnboardingPackageButton.isEnabled = hasOnboardingPackage
        resetButton.isEnabled = hasUser
    }

    private suspend fun resetLocalStateWithRemoteRetire(user: String): String {
        val keysJson = store.readKeys(user)
        var retiredRemotely = false
        if (!keysJson.isNullOrBlank()) {
            val server = serverInput.text.toString().trim()
            require(server.isNotBlank()) { "server URL is empty" }
            val profile = loadUserProfile(keysJson)
            require(profile.userId == user) {
                "user mismatch: current input '$user' vs stored keys '${profile.userId}'"
            }
            val api = ApiClientFactory.create(server)
            ApiClientFactory.validateCapabilities(api.getCapabilities(), suiteLabel(profile.suite))
            val response = api.retireCurrentDevice(
                userId = user,
                headers = buildRetireDeviceAuthHeaders(keysJson, user).toHeaderMap(),
            )
            check(response.user_id == user) {
                "retire response user mismatch: expected '$user' got '${response.user_id}'"
            }
            check(response.retired_device_id == profile.deviceId) {
                "retire response device mismatch: expected '${profile.deviceId}' got '${response.retired_device_id}'"
            }
            retiredRemotely = true
        }
        lastDeviceSnapshot = null
        store.wipeUserState(user)
        userInput.setText(store.loadSetup().userId)
        managedDeviceInput.setText(defaultManagedDeviceId(userInput.text.toString().trim()))
        renderSecurityInfo()
        syncActionAvailability()
        return if (retiredRemotely) {
            "Retired current device and cleared local state for $user"
        } else {
            "Cleared local state for $user"
        }
    }

    private fun runSecurityAction(action: String, block: suspend () -> String) {
        lifecycleScope.launch {
            runCatching {
                block()
            }.onSuccess { message ->
                renderSecurityInfo()
                statusText.text = message
                Toast.makeText(this@SecurityInfoActivity, message, Toast.LENGTH_SHORT).show()
            }.onFailure {
                val mapped = UiErrorMapper.fromThrowable(it, action)
                statusText.text = mapped.headline
                Toast.makeText(this@SecurityInfoActivity, mapped.headline, Toast.LENGTH_LONG).show()
            }
        }
    }

    private suspend fun listLinkedDevices(): String {
        val user = requireCurrentUser()
        val context = loadDeviceManagementContext(user)
        val response = fetchDeviceSnapshot(context)
        return "Loaded ${response.devices.size} device record(s) for ${response.user_id}"
    }

    private suspend fun linkManagedDevice(): String {
        val user = requireCurrentUser()
        val targetDevice = managedDeviceInput.text.toString().trim()
        require(targetDevice.isNotBlank()) { "managed device id is empty" }
        val context = loadDeviceManagementContext(user)
        require(targetDevice != context.profile.deviceId) {
            "managed device id must differ from the authenticated device id"
        }
        val response = context.api.linkDevice(
            userId = user,
            headers = buildLinkDeviceAuthHeaders(context.keysJson, user, targetDevice).toHeaderMap(),
            request = LinkDeviceRequest(new_device_id = targetDevice),
        )
        check(response.user_id == user) {
            "link response user mismatch: expected '$user' got '${response.user_id}'"
        }
        check(response.linked_device_id == targetDevice) {
            "link response device mismatch: expected '$targetDevice' got '${response.linked_device_id}'"
        }
        fetchDeviceSnapshot(context)
        return "Linked device ${response.linked_device_id} for ${response.user_id}"
    }

    private suspend fun revokeManagedDevice(): String {
        val user = requireCurrentUser()
        val targetDevice = managedDeviceInput.text.toString().trim()
        require(targetDevice.isNotBlank()) { "managed device id is empty" }
        val context = loadDeviceManagementContext(user)
        require(targetDevice != context.profile.deviceId) {
            "managed device id matches the current device; use Reset Local State for self-retirement"
        }
        val response = context.api.revokeDevice(
            userId = user,
            targetDeviceId = targetDevice,
            headers = buildRevokeDeviceAuthHeaders(context.keysJson, user, targetDevice).toHeaderMap(),
        )
        check(response.user_id == user) {
            "revoke response user mismatch: expected '$user' got '${response.user_id}'"
        }
        check(response.revoked_device_id == targetDevice) {
            "revoke response device mismatch: expected '$targetDevice' got '${response.revoked_device_id}'"
        }
        fetchDeviceSnapshot(context)
        return "Revoked device ${response.revoked_device_id} for ${response.user_id}"
    }

    private suspend fun prepareSecondaryDeviceOnboardingPackage(): String {
        val user = requireCurrentUser()
        val targetDevice = managedDeviceInput.text.toString().trim()
        require(targetDevice.isNotBlank()) { "managed device id is empty" }
        val packagePassphrase = onboardingPassphraseInput.text.toString()
        require(packagePassphrase.isNotBlank()) {
            "onboarding package passphrase is empty"
        }
        val context = loadDeviceManagementContext(user)
        require(targetDevice != context.profile.deviceId) {
            "managed device id must differ from the authenticated device id"
        }
        val response = context.api.linkDevice(
            userId = user,
            headers = buildLinkDeviceAuthHeaders(context.keysJson, user, targetDevice).toHeaderMap(),
            request = LinkDeviceRequest(new_device_id = targetDevice),
        )
        check(response.user_id == user) {
            "link response user mismatch: expected '$user' got '${response.user_id}'"
        }
        check(response.linked_device_id == targetDevice) {
            "link response device mismatch: expected '$targetDevice' got '${response.linked_device_id}'"
        }
        val packageJson = prepareSecondaryDevicePackage(
            context.keysJson,
            targetDevice,
            serverInput.text.toString().trim(),
            16u,
            packagePassphrase,
        )
        onboardingPackageInput.setText(packageJson)
        fetchDeviceSnapshot(context)
        copyOnboardingPackageToClipboard()
        return "Prepared linked device ${response.linked_device_id} and copied onboarding package"
    }

    private suspend fun loadIdentityLog(): String {
        val user = requireCurrentUser()
        val context = loadDeviceManagementContext(user)
        val response = context.api.identityLog(
            userId = user,
            headers = buildIdentityLogAuthHeaders(context.keysJson, user).toHeaderMap(),
        )
        check(response.user_id == user) {
            "identity log response user mismatch: expected '$user' got '${response.user_id}'"
        }
        lastIdentityLogSnapshot = response
        return "Loaded ${response.events.size} identity event(s) for ${response.user_id}"
    }

    private suspend fun rotateIdentity(): String {
        val user = requireCurrentUser()
        val targetDevice = managedDeviceInput.text.toString().trim()
        require(targetDevice.isNotBlank()) { "managed device id is empty" }
        val context = loadDeviceManagementContext(user)
        require(targetDevice != context.profile.deviceId) {
            "managed device id must differ from the authenticated device id"
        }

        val nextKeysJson = generateIdentityKeys(
            user,
            targetDevice,
            context.profile.suite,
            16u,
        )
        val rotateInitPayload = buildRotateInitPayload(nextKeysJson)
        val rotateInitResponse = context.api.rotateInit(
            userId = user,
            headers = buildRotateInitAuthHeaders(
                context.keysJson,
                user,
                rotateInitPayload.newIdentityX25519Pub,
                rotateInitPayload.newIdentitySigPub,
            ).toHeaderMap(),
            request = RotateInitRequest(
                new_identity_x25519_pub = rotateInitPayload.newIdentityX25519Pub,
                new_identity_sig_pub = rotateInitPayload.newIdentitySigPub,
                new_device_id = rotateInitPayload.newDeviceId,
            ),
        )
        check(rotateInitResponse.user_id == user) {
            "rotate-init response user mismatch: expected '$user' got '${rotateInitResponse.user_id}'"
        }

        val rotateConfirmPayload = buildRotateConfirmPayload(
            context.keysJson,
            nextKeysJson,
            user,
            rotateInitResponse.challenge_id,
            rotateInitResponse.challenge_nonce,
        )
        val rotateConfirmResponse = context.api.rotateConfirm(
            userId = user,
            headers = buildRotateConfirmAuthHeaders(
                context.keysJson,
                user,
                rotateConfirmPayload.challengeId,
                rotateConfirmPayload.sigByCurrentIdentity,
                rotateConfirmPayload.sigByNewIdentity,
            ).toHeaderMap(),
            request = RotateConfirmRequest(
                challenge_id = rotateConfirmPayload.challengeId,
                sig_by_current_identity = rotateConfirmPayload.sigByCurrentIdentity,
                sig_by_new_identity = rotateConfirmPayload.sigByNewIdentity,
            ),
        )
        check(rotateConfirmResponse.user_id == user) {
            "rotate-confirm response user mismatch: expected '$user' got '${rotateConfirmResponse.user_id}'"
        }

        val publishPayload = buildPublishPrekeysPayload(nextKeysJson)
        context.api.publishPrekeys(
            user,
            buildPrekeysAuthHeaders(nextKeysJson, user).toHeaderMap(),
            PublishPrekeysRequest(
                signed_prekey_x25519_pub = publishPayload.signedPrekeyX25519Pub,
                sig_over_spk = publishPayload.sigOverSpk,
                pq_signed_prekey_pub_mlkem768 = publishPayload.pqSignedPrekeyPubMlkem768,
                sig_over_pqspk = publishPayload.sigOverPqspk,
                one_time_prekeys_x25519 = publishPayload.oneTimePrekeysX25519,
                one_time_prekeys_mlkem768 = publishPayload.oneTimePrekeysMlkem768,
            ),
        )

        val priorPeer = store.loadSetup().peerUserId.ifBlank { "bob" }
        store.wipeUserState(user)
        store.writeKeys(user, nextKeysJson)
        store.saveSetup(
            SetupConfig(
                serverUrl = serverInput.text.toString().trim(),
                userId = user,
                deviceId = targetDevice,
                suiteLabel = suiteLabel(context.profile.suite),
                peerUserId = priorPeer,
            ),
        )
        val nextProgress = SetupProgress().adoptLinkedDevice()
        store.saveProgress(user, nextProgress)

        lastDeviceSnapshot = context.api.listDevices(
            userId = user,
            headers = buildListDevicesAuthHeaders(nextKeysJson, user).toHeaderMap(),
        )
        lastIdentityLogSnapshot = context.api.identityLog(
            userId = user,
            headers = buildIdentityLogAuthHeaders(nextKeysJson, user).toHeaderMap(),
        )
        userInput.setText(user)
        managedDeviceInput.setText(defaultManagedDeviceId(user))
        renderSecurityInfo()
        syncActionAvailability()
        return "Rotated identity to ${targetDevice} (version ${rotateConfirmResponse.identity_key_version}) and published new prekeys"
    }

    private fun copyOnboardingPackageToClipboard() {
        val packageJson = onboardingPackageInput.text.toString().trim()
        if (packageJson.isBlank()) {
            Toast.makeText(this, "No onboarding package to copy.", Toast.LENGTH_SHORT).show()
            return
        }
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("pqmsg-secondary-device-package", packageJson))
        Toast.makeText(this, "Copied onboarding package to clipboard.", Toast.LENGTH_SHORT).show()
    }

    private suspend fun loadDeviceManagementContext(user: String): DeviceManagementContext {
        val keysJson = store.readKeys(user) ?: error("missing keys for user '$user'")
        val profile = loadUserProfile(keysJson)
        require(profile.userId == user) {
            "user mismatch: current input '$user' vs stored keys '${profile.userId}'"
        }
        val server = serverInput.text.toString().trim()
        require(server.isNotBlank()) { "server URL is empty" }
        val api = ApiClientFactory.create(server)
        val capabilities = api.getCapabilities()
        ApiClientFactory.validateCapabilities(capabilities, suiteLabel(profile.suite))
        return DeviceManagementContext(keysJson, profile, api, capabilities)
    }

    private suspend fun fetchDeviceSnapshot(context: DeviceManagementContext): DeviceListResponse {
        val response = context.api.listDevices(
            userId = context.profile.userId,
            headers = buildListDevicesAuthHeaders(context.keysJson, context.profile.userId).toHeaderMap(),
        )
        check(response.user_id == context.profile.userId) {
            "device list response user mismatch: expected '${context.profile.userId}' got '${response.user_id}'"
        }
        lastDeviceSnapshot = response
        return response
    }

    private fun requireCurrentUser(): String {
        val user = userInput.text.toString().trim()
        require(user.isNotBlank()) { "user id is empty" }
        return user
    }

    private fun buildDeviceSnapshotText(user: String): String {
        if (user.isBlank()) {
            return "Linked Devices\nEnter a user id to inspect linked devices"
        }
        val snapshot = lastDeviceSnapshot
        if (snapshot == null || snapshot.user_id != user) {
            return "Linked Devices\nNot checked for user '$user'"
        }
        if (snapshot.devices.isEmpty()) {
            return "Linked Devices\nNo linked devices returned for user '$user'"
        }
        return buildString {
            append("Linked Devices\n")
            append(
                snapshot.devices.joinToString("\n") { device ->
                    val state = if (device.active) {
                        "active"
                    } else {
                        "revoked at ${device.revoked_at ?: "unknown"}"
                    }
                    "${device.device_id}: $state (linked ${device.linked_at})"
                }
            )
        }
    }

    private fun buildIdentityLogText(user: String): String {
        if (user.isBlank()) {
            return "Identity Log\nEnter a user id to inspect identity events"
        }
        val snapshot = lastIdentityLogSnapshot
        if (snapshot == null || snapshot.user_id != user) {
            return "Identity Log\nNot checked for user '$user'"
        }
        if (snapshot.events.isEmpty()) {
            return "Identity Log\nNo identity events returned for user '$user'"
        }
        return buildString {
            append("Identity Log\n")
            append(
                snapshot.events.joinToString("\n") { event ->
                    "v${event.version} ${event.event_type} ${event.device_id} ${event.changed_at}"
                }
            )
        }
    }

    private fun suiteLabel(suite: Suite): String {
        return if (suite == Suite.KYBER768) {
            "kyber768"
        } else {
            "ml-kem-768"
        }
    }

    private fun defaultManagedDeviceId(user: String): String {
        if (user.isBlank()) {
            return ""
        }
        return "$user-device-2"
    }

    private data class DeviceManagementContext(
        val keysJson: String,
        val profile: uniffi.pqmsg_android.UserProfile,
        val api: PqmsgApi,
        val capabilities: ServerCapabilitiesResponse,
    )
}
