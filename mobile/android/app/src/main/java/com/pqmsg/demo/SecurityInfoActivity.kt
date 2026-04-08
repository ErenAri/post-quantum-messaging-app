package com.pqmsg.demo

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import com.google.gson.Gson
import kotlinx.coroutines.launch
import uniffi.pqmsg_android.Suite
import uniffi.pqmsg_android.activeCryptoProfile
import uniffi.pqmsg_android.buildDeleteAccountAuthHeaders
import uniffi.pqmsg_android.buildIdentityLogAuthHeaders
import uniffi.pqmsg_android.buildLinkDeviceAuthHeaders
import uniffi.pqmsg_android.buildListDevicesAuthHeaders
import uniffi.pqmsg_android.buildPrekeysAuthHeaders
import uniffi.pqmsg_android.buildProfileGetAuthHeaders
import uniffi.pqmsg_android.buildProfileUpsertAuthHeaders
import uniffi.pqmsg_android.buildRevokeDeviceAuthHeaders
import uniffi.pqmsg_android.buildRetireDeviceAuthHeaders
import uniffi.pqmsg_android.buildRotateConfirmAuthHeaders
import uniffi.pqmsg_android.buildRotateConfirmPayload
import uniffi.pqmsg_android.buildRotateInitAuthHeaders
import uniffi.pqmsg_android.buildRotateInitPayload
import uniffi.pqmsg_android.buildPublishPrekeysPayload
import uniffi.pqmsg_android.generateIdentityKeys
import uniffi.pqmsg_android.loadUserProfile
import uniffi.pqmsg_android.openSecondaryDevicePackage
import uniffi.pqmsg_android.prepareSecondaryDevicePackage
import uniffi.pqmsg_android.verifyTransparencyProof

class SecurityInfoActivity : AppCompatActivity() {
    private lateinit var store: LocalStateStore
    private lateinit var serverInput: EditText
    private lateinit var userInput: EditText
    private lateinit var managedDeviceInput: EditText
    private lateinit var onboardingPassphraseInput: EditText
    private lateinit var onboardingPackageInput: EditText
    private lateinit var onboardingPreviewText: TextView
    private lateinit var toggleRecoveryButton: Button
    private lateinit var recoveryInputsSection: LinearLayout
    private lateinit var recoveryActionsSection: LinearLayout
    private lateinit var refreshButton: Button
    private lateinit var privacyPolicyButton: Button
    private lateinit var editProfileButton: Button
    private lateinit var listDevicesButton: Button
    private lateinit var linkDeviceButton: Button
    private lateinit var revokeDeviceButton: Button
    private lateinit var listIdentityLogButton: Button
    private lateinit var rotateIdentityButton: Button
    private lateinit var prepareSecondaryDeviceButton: Button
    private lateinit var copyOnboardingPackageButton: Button
    private lateinit var deleteAccountButton: Button
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
    private var lastTransparencyProofSnapshot: TransparencyProofResponse? = null
    private var lastTransparencyVerification: uniffi.pqmsg_android.TransparencyVerificationResult? = null
    private var lastTransparencyUsedCheckpoint: Boolean = false
    private var lastCapabilitiesSnapshot: ServerCapabilitiesResponse? = null
    private val clipboardClearHandler = Handler(Looper.getMainLooper())
    private var pendingClipboardClear: Runnable? = null
    private val gson = Gson()
    private var recoveryToolsExpanded: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_security_info)
        store = LocalStateStore(this)

        serverInput = findViewById(R.id.editSecurityServer)
        userInput = findViewById(R.id.editSecurityUser)
        managedDeviceInput = findViewById(R.id.editSecurityManagedDevice)
        onboardingPassphraseInput = findViewById(R.id.editSecurityOnboardingPassphrase)
        onboardingPackageInput = findViewById(R.id.editSecurityOnboardingPackage)
        onboardingPreviewText = findViewById(R.id.textSecurityOnboardingPackagePreview)
        toggleRecoveryButton = findViewById(R.id.buttonToggleSecurityRecovery)
        recoveryInputsSection = findViewById(R.id.sectionSecurityRecoveryInputs)
        recoveryActionsSection = findViewById(R.id.sectionSecurityRecoveryActions)
        refreshButton = findViewById(R.id.buttonRefreshSecurityInfo)
        privacyPolicyButton = findViewById(R.id.buttonOpenPrivacyPolicy)
        editProfileButton = findViewById(R.id.buttonEditShareableProfile)
        listDevicesButton = findViewById(R.id.buttonListDevices)
        linkDeviceButton = findViewById(R.id.buttonLinkDevice)
        revokeDeviceButton = findViewById(R.id.buttonRevokeDevice)
        listIdentityLogButton = findViewById(R.id.buttonListIdentityLog)
        rotateIdentityButton = findViewById(R.id.buttonRotateIdentity)
        prepareSecondaryDeviceButton = findViewById(R.id.buttonPrepareSecondaryDevicePackage)
        copyOnboardingPackageButton = findViewById(R.id.buttonCopyOnboardingPackage)
        deleteAccountButton = findViewById(R.id.buttonDeleteAccount)
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
            lastTransparencyProofSnapshot = null
            lastTransparencyVerification = null
            lastTransparencyUsedCheckpoint = false
            renderSecurityInfo()
            syncActionAvailability()
        }
        userInput.doAfterTextChanged {
            lastDeviceSnapshot = null
            lastIdentityLogSnapshot = null
            lastTransparencyProofSnapshot = null
            lastTransparencyVerification = null
            lastTransparencyUsedCheckpoint = false
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
            if (!it.isNullOrBlank()) {
                recoveryToolsExpanded = true
                syncRecoveryToolVisibility()
            }
            refreshOnboardingPackagePreview()
            syncActionAvailability()
        }
        onboardingPassphraseInput.doAfterTextChanged {
            if (!it.isNullOrBlank()) {
                recoveryToolsExpanded = true
                syncRecoveryToolVisibility()
            }
            refreshOnboardingPackagePreview()
            syncActionAvailability()
        }
        toggleRecoveryButton.setOnClickListener {
            recoveryToolsExpanded = !recoveryToolsExpanded
            syncRecoveryToolVisibility()
        }
        refreshButton.setOnClickListener { renderSecurityInfo() }
        privacyPolicyButton.setOnClickListener {
            startActivity(Intent(this, PrivacyPolicyActivity::class.java))
        }
        editProfileButton.setOnClickListener { showShareableProfileEditor() }
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
        deleteAccountButton.setOnClickListener { confirmDeleteAccount() }
        resetButton.setOnClickListener { confirmResetLocalState() }
        backButton.setOnClickListener { finish() }

        renderSecurityInfo()
        refreshOnboardingPackagePreview()
        syncActionAvailability()
        syncRecoveryToolVisibility()
    }

    override fun onDestroy() {
        pendingClipboardClear?.let { clipboardClearHandler.removeCallbacks(it) }
        pendingClipboardClear = null
        super.onDestroy()
    }

    private fun renderSecurityInfo() {
        val server = serverInput.text.toString().trim()
        val user = userInput.text.toString().trim()

        val cryptoProfile = runCatching { activeCryptoProfile() }
            .getOrElse { "Unavailable: ${it.message ?: "native runtime error"}" }
        profileText.text = getString(R.string.security_profile_summary, cryptoProfile)

        val transportPolicy = runCatching {
            val policy = ApiClientFactory.resolveTransportPolicy(
                base = server,
                allowCleartextDemo = BuildConfig.ALLOW_CLEARTEXT_DEMO,
                tlsPinSha256 = BuildConfig.TLS_PIN_SHA256,
                tlsBackupPinSha256 = BuildConfig.TLS_BACKUP_PIN_SHA256,
            )
            val pinLine = if (policy.certificatePins.isEmpty()) {
                "TLS pins: none"
            } else {
                "TLS pins:\n${policy.certificatePins.joinToString(separator = "\n") { "- $it" }}"
            }
            "Address: ${policy.baseUrl}\n$pinLine"
        }.getOrElse {
            it.message ?: "unavailable"
        }
        transportText.text = getString(R.string.security_transport_summary, transportPolicy)
        if (server.isNotBlank()) {
            val requestedServer = server
            lifecycleScope.launch {
                runCatching {
                    ApiClientFactory.create(requestedServer).getCapabilities()
                }.onSuccess { capabilities ->
                    if (serverInput.text.toString().trim() != requestedServer) {
                        return@onSuccess
                    }
                    lastCapabilitiesSnapshot = capabilities
                    val supportedClients = capabilities.supported_beta_clients.joinToString(", ")
                        .ifBlank { "none" }
                    transportText.text = getString(
                        R.string.security_transport_capabilities,
                        transportPolicy,
                        supportedClients,
                        capabilities.web_client_policy,
                    )
                }.onFailure {
                    if (serverInput.text.toString().trim() != requestedServer) {
                        return@onFailure
                    }
                    lastCapabilitiesSnapshot = null
                    transportText.text = getString(
                        R.string.security_transport_capabilities_unavailable,
                        transportPolicy,
                        it.message ?: "unavailable",
                    )
                }
            }
        } else {
            lastCapabilitiesSnapshot = null
        }

        val pinLines = store.listIdentityPins(user)
            .map {
                "${it.peerUserId}: ${it.pin.fingerprintSha256} (v${it.pin.identityKeyVersion})"
        }
        pinsText.text = if (pinLines.isEmpty()) {
            getString(R.string.security_pins_empty, user)
        } else {
            getString(R.string.security_pins_list, pinLines.joinToString("\n"))
        }
        devicesText.text = buildDeviceSnapshotText(user)
        identityLogText.text = buildIdentityLogText(user)

        val sessionCount = store.countSessions(user)
        val conversations = store.listConversations(user)
        localStateText.text = getString(
            R.string.security_local_state_summary,
            sessionCount,
            conversations.size,
            user,
        )
    }

    private fun confirmResetLocalState() {
        val user = userInput.text.toString().trim()
        if (user.isBlank()) {
            Toast.makeText(
                this,
                getString(R.string.security_enter_user_before_reset),
                Toast.LENGTH_SHORT,
            ).show()
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

    private fun confirmDeleteAccount() {
        val user = userInput.text.toString().trim()
        if (user.isBlank()) {
            Toast.makeText(
                this,
                getString(R.string.security_enter_user_before_delete),
                Toast.LENGTH_SHORT,
            ).show()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.delete_account_title)
            .setMessage(getString(R.string.delete_account_message, user))
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.button_delete_account) { _, _ ->
                lifecycleScope.launch {
                    runCatching {
                        deleteCurrentAccount(user)
                    }.onSuccess { message ->
                        Toast.makeText(this@SecurityInfoActivity, message, Toast.LENGTH_LONG).show()
                        startActivity(Intent(this@SecurityInfoActivity, MainActivity::class.java))
                        finishAffinity()
                    }.onFailure {
                        val mapped = UiErrorMapper.fromThrowable(it, "Delete account")
                        statusText.text = mapped.headline
                        Toast.makeText(this@SecurityInfoActivity, mapped.headline, Toast.LENGTH_LONG).show()
                    }
                }
            }
            .show()
    }

    private fun showShareableProfileEditor() {
        val user = userInput.text.toString().trim()
        if (user.isBlank()) {
            statusText.text = getString(R.string.security_enter_user_before_profile)
            return
        }
        lifecycleScope.launch {
            runCatching {
                loadEditableProfile(user)
            }.onSuccess { profile ->
                val displayNameInput = EditText(this@SecurityInfoActivity).apply {
                    hint = getString(R.string.hint_profile_display_name)
                    setText(profile.display_name.orEmpty())
                }
                val usernameInput = EditText(this@SecurityInfoActivity).apply {
                    hint = getString(R.string.hint_shareable_username)
                    setText(profile.username?.let { "@$it" }.orEmpty())
                }
                val lookupEnabledInput = CheckBox(this@SecurityInfoActivity).apply {
                    text = getString(R.string.label_allow_username_lookup)
                    isChecked = profile.username_lookup_enabled ?: false
                }
                val container = LinearLayout(this@SecurityInfoActivity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(24, 8, 24, 0)
                    addView(displayNameInput)
                    addView(usernameInput)
                    addView(lookupEnabledInput)
                }
                AlertDialog.Builder(this@SecurityInfoActivity)
                    .setTitle(R.string.button_edit_shareable_profile)
                    .setView(container)
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton(R.string.button_save_shareable_profile) { _, _ ->
                        lifecycleScope.launch {
                            runCatching {
                                updateShareableProfile(
                                    displayNameInput.text?.toString().orEmpty(),
                                    usernameInput.text?.toString().orEmpty(),
                                    lookupEnabledInput.isChecked,
                                )
                            }.onSuccess { message ->
                                renderSecurityInfo()
                                statusText.text = message
                                Toast.makeText(this@SecurityInfoActivity, message, Toast.LENGTH_SHORT).show()
                            }.onFailure {
                                val mapped = UiErrorMapper.fromThrowable(it, "Update shareable profile")
                                statusText.text = mapped.headline
                                Toast.makeText(this@SecurityInfoActivity, mapped.headline, Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                    .show()
            }.onFailure {
                val mapped = UiErrorMapper.fromThrowable(it, "Load shareable profile")
                statusText.text = mapped.headline
                Toast.makeText(this@SecurityInfoActivity, mapped.headline, Toast.LENGTH_LONG).show()
            }
        }
    }

    private suspend fun loadEditableProfile(user: String): UserProfileResponse {
        val context = loadDeviceManagementContext(user)
        return context.api.getUserProfile(
            userId = user,
            headers = buildProfileGetAuthHeaders(context.keysJson, user).toHeaderMap(),
        )
    }

    private suspend fun updateShareableProfile(
        displayName: String,
        username: String,
        usernameLookupEnabled: Boolean,
    ): String {
        val user = requireCurrentUser()
        val context = loadDeviceManagementContext(user)
        val normalizedDisplayName = displayName.trim().ifBlank { null }
        val normalizedUsername = username.trim().ifBlank { null }
        val response = context.api.upsertUserProfile(
            userId = user,
            headers = buildProfileUpsertAuthHeaders(
                context.keysJson,
                user,
                normalizedDisplayName.orEmpty(),
                normalizedUsername.orEmpty(),
                normalizedUsername != null && usernameLookupEnabled,
                "",
                "",
            ).toHeaderMap(),
            request = UpsertProfileRequest(
                display_name = normalizedDisplayName,
                username = normalizedUsername,
                username_lookup_enabled = if (normalizedUsername != null) usernameLookupEnabled else false,
                avatar_mime = null,
                avatar_bytes_base64 = null,
            ),
        )
        val summary = response.username?.let { usernameValue ->
            "@$usernameValue${if (response.username_lookup_enabled == true) " (lookup on)" else " (invite-only)"}"
        } ?: "no shareable username"
        return "Updated shareable profile: $summary"
    }

    private fun syncActionAvailability() {
        val hasUser = userInput.text.toString().trim().isNotBlank()
        val hasManagedDevice = managedDeviceInput.text.toString().trim().isNotBlank()
        val hasOnboardingPackage = onboardingPackageInput.text.toString().trim().isNotBlank()
        privacyPolicyButton.isEnabled = true
        editProfileButton.isEnabled = hasUser
        listDevicesButton.isEnabled = hasUser
        linkDeviceButton.isEnabled = hasUser && hasManagedDevice
        revokeDeviceButton.isEnabled = hasUser && hasManagedDevice
        listIdentityLogButton.isEnabled = hasUser
        rotateIdentityButton.isEnabled = hasUser && hasManagedDevice
        prepareSecondaryDeviceButton.isEnabled = hasUser && hasManagedDevice
        copyOnboardingPackageButton.isEnabled = hasOnboardingPackage
        deleteAccountButton.isEnabled = hasUser
        resetButton.isEnabled = hasUser
    }

    private fun syncRecoveryToolVisibility() {
        recoveryInputsSection.visibility = if (recoveryToolsExpanded) View.VISIBLE else View.GONE
        recoveryActionsSection.visibility = if (recoveryToolsExpanded) View.VISIBLE else View.GONE
        toggleRecoveryButton.text =
            getString(
                if (recoveryToolsExpanded) {
                    R.string.button_hide_recovery_tools
                } else {
                    R.string.button_show_recovery_tools
                },
            )
    }

    private fun refreshOnboardingPackagePreview() {
        val packagePassphrase = onboardingPassphraseInput.text.toString()
        val packageJson = onboardingPackageInput.text.toString().trim()
        if (packagePassphrase.isBlank() || packageJson.isBlank()) {
            onboardingPreviewText.visibility = View.GONE
            onboardingPreviewText.text = getString(R.string.onboarding_package_preview_default)
            return
        }
        onboardingPreviewText.visibility = View.VISIBLE
        onboardingPreviewText.text =
            runCatching {
                formatLinkedDevicePackagePreview(
                    openSecondaryDevicePackage(packageJson, packagePassphrase),
                )
            }.getOrElse {
                getString(
                    R.string.security_preview_invalid,
                    it.message ?: getString(R.string.setup_preview_invalid_fallback),
                )
            }
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
            getString(R.string.security_reset_retired_status, user)
        } else {
            getString(R.string.security_reset_local_only_status, user)
        }
    }

    private suspend fun deleteCurrentAccount(user: String): String {
        val context = loadDeviceManagementContext(user)
        val response = context.api.deleteAccount(
            userId = user,
            headers = buildDeleteAccountAuthHeaders(context.keysJson, user).toHeaderMap(),
        )
        check(response.user_id == user) {
            "delete account response user mismatch: expected '$user' got '${response.user_id}'"
        }
        check(response.deleted_device_id == context.profile.deviceId) {
            "delete account response device mismatch: expected '${context.profile.deviceId}' got '${response.deleted_device_id}'"
        }
        lastDeviceSnapshot = null
        lastIdentityLogSnapshot = null
        lastTransparencyProofSnapshot = null
        lastTransparencyVerification = null
        lastTransparencyUsedCheckpoint = false
        lastCapabilitiesSnapshot = null
        store.wipeUserState(user)
        return getString(R.string.security_account_deleted_status, user)
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
        return getString(R.string.security_devices_loaded_status, response.devices.size, response.user_id)
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
        return getString(R.string.security_linked_device_status, response.linked_device_id)
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
        return getString(R.string.security_revoked_device_status, response.revoked_device_id)
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
        return getString(R.string.security_prepared_package_status, response.linked_device_id)
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
        val previousCheckpointJson = store.readTransparencyCheckpoint(
            serverInput.text.toString().trim(),
            user,
        )
        lastTransparencyUsedCheckpoint = !previousCheckpointJson.isNullOrBlank()
        val previousTreeSize = previousCheckpointJson?.let {
            runCatching {
                gson.fromJson(it, TransparencySignedTreeHeadResponse::class.java).tree_size
            }.getOrNull()
        }
        val proof = context.api.getTransparencyProof(
            userId = user,
            previousTreeSize = previousTreeSize,
        )
        check(proof.user_id == user) {
            "transparency proof response user mismatch: expected '$user' got '${proof.user_id}'"
        }
        val verification = verifyTransparencyProof(
            gson.toJson(proof),
            context.capabilities.transparency_log_issuer_ed25519_pub,
            previousCheckpointJson,
        )
        response.events.firstOrNull()?.let { latest ->
            check(latest.version.toULong() == verification.leafVersion) {
                "identity log latest version ${latest.version} does not match transparency leaf ${verification.leafVersion}"
            }
            check(latest.identity_x25519_pub == proof.leaf.identity_x25519_pub) {
                "identity log and transparency leaf x25519 keys do not match"
            }
            check((latest.identity_pq_sig_pub ?: "") == (proof.leaf.identity_pq_sig_pub ?: "")) {
                "identity log and transparency leaf PQ identity keys do not match"
            }
        }
        store.writeTransparencyCheckpoint(
            serverInput.text.toString().trim(),
            user,
            gson.toJson(proof.signed_tree_head),
        )
        lastTransparencyProofSnapshot = proof
        lastTransparencyVerification = verification
        return if (verification.consistencyVerified) {
            "Loaded ${response.events.size} identity event(s) for ${response.user_id} and verified append-only transparency growth"
        } else {
            "Loaded ${response.events.size} identity event(s) for ${response.user_id} and verified the current transparency proof"
        }
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
                rotateInitPayload.newIdentityPqSigPub,
            ).toHeaderMap(),
            request = RotateInitRequest(
                new_identity_x25519_pub = rotateInitPayload.newIdentityX25519Pub,
                new_identity_sig_pub = rotateInitPayload.newIdentitySigPub,
                new_identity_pq_sig_pub = rotateInitPayload.newIdentityPqSigPub,
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
                rotateConfirmPayload.pqSigByCurrentIdentity,
                rotateConfirmPayload.pqSigByNewIdentity,
            ).toHeaderMap(),
            request = RotateConfirmRequest(
                challenge_id = rotateConfirmPayload.challengeId,
                sig_by_current_identity = rotateConfirmPayload.sigByCurrentIdentity,
                sig_by_new_identity = rotateConfirmPayload.sigByNewIdentity,
                pq_sig_by_current_identity = rotateConfirmPayload.pqSigByCurrentIdentity,
                pq_sig_by_new_identity = rotateConfirmPayload.pqSigByNewIdentity,
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
                pq_sig_over_spk = publishPayload.pqSigOverSpk,
                pq_sig_over_pqspk = publishPayload.pqSigOverPqspk,
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
            Toast.makeText(
                this,
                getString(R.string.security_no_package_to_copy),
                Toast.LENGTH_SHORT,
            ).show()
            return
        }
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("pqmsg-secondary-device-package", packageJson))
        scheduleOnboardingClipboardClear(packageJson)
        Toast.makeText(
            this,
            getString(
                R.string.linked_device_package_copied_notice,
                LINKED_DEVICE_PACKAGE_CLIPBOARD_CLEAR_DELAY_SECONDS,
            ),
            Toast.LENGTH_SHORT,
        ).show()
    }

    private fun scheduleOnboardingClipboardClear(expectedPackageJson: String) {
        pendingClipboardClear?.let { clipboardClearHandler.removeCallbacks(it) }
        val runnable = Runnable {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = clipboard.primaryClip
            val currentText = clip
                ?.takeIf { it.itemCount > 0 }
                ?.getItemAt(0)
                ?.coerceToText(this)
                ?.toString()
            if (currentText == expectedPackageJson) {
                clipboard.setPrimaryClip(
                    ClipData.newPlainText("pqmsg-secondary-device-package", ""),
                )
                statusText.text = getString(
                    R.string.linked_device_package_clipboard_cleared,
                    LINKED_DEVICE_PACKAGE_CLIPBOARD_CLEAR_DELAY_SECONDS,
                )
            }
        }
        pendingClipboardClear = runnable
        clipboardClearHandler.postDelayed(
            runnable,
            LINKED_DEVICE_PACKAGE_CLIPBOARD_CLEAR_DELAY_SECONDS * 1000L,
        )
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
            return getString(R.string.security_device_snapshot_prompt)
        }
        val snapshot = lastDeviceSnapshot
        if (snapshot == null || snapshot.user_id != user) {
            return getString(R.string.security_device_snapshot_idle, user)
        }
        if (snapshot.devices.isEmpty()) {
            return getString(R.string.security_device_snapshot_empty, user)
        }
        val currentDeviceId = store.loadSetup().deviceId
        return buildString {
            append(getString(R.string.security_device_snapshot_title))
            append('\n')
            append(
                snapshot.devices.joinToString("\n\n") { device ->
                    if (device.active && device.device_id == currentDeviceId) {
                        getString(
                            R.string.security_device_snapshot_this_phone,
                            device.device_id,
                            device.linked_at,
                        )
                    } else if (device.active) {
                        getString(
                            R.string.security_device_snapshot_active,
                            device.device_id,
                            device.linked_at,
                        )
                    } else {
                        getString(
                            R.string.security_device_snapshot_revoked,
                            device.device_id,
                            device.revoked_at ?: "unknown",
                        )
                    }
                }
            )
        }
    }

    private fun buildIdentityLogText(user: String): String {
        if (user.isBlank()) {
            return getString(R.string.security_identity_log_prompt)
        }
        val snapshot = lastIdentityLogSnapshot
        if (snapshot == null || snapshot.user_id != user) {
            return getString(R.string.security_identity_log_idle, user)
        }
        if (snapshot.events.isEmpty()) {
            return getString(R.string.security_identity_log_empty, user)
        }
        return buildString {
            append(getString(R.string.security_identity_log_title))
            append('\n')
            lastTransparencyVerification?.let { verification ->
                append(getString(R.string.security_identity_verified, verification.leafVersion, verification.treeSize))
                append('\n')
                append(
                    if (lastTransparencyUsedCheckpoint && verification.consistencyVerified) {
                        getString(R.string.security_identity_checkpoint_verified)
                    } else if (lastTransparencyUsedCheckpoint) {
                        getString(R.string.security_identity_current_only)
                    } else {
                        getString(R.string.security_identity_first_checkpoint)
                    }
                )
                append('\n')
            }
            val previewEvents = snapshot.events.take(5)
            append(
                previewEvents.joinToString("\n\n") { event ->
                    getString(
                        R.string.security_identity_event_line,
                        event.version.toString(),
                        event.event_type.lowercase().replace('_', ' '),
                        event.device_id,
                        event.changed_at,
                    )
                }
            )
            if (snapshot.events.size > previewEvents.size) {
                append("\n\n")
                append(
                    getString(
                        R.string.security_identity_more_events,
                        snapshot.events.size - previewEvents.size,
                    ),
                )
            }
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
