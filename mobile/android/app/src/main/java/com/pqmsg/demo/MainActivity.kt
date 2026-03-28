package com.pqmsg.demo

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import uniffi.pqmsg_android.SecondaryDeviceOnboardingPackage
import uniffi.pqmsg_android.activeCryptoProfile
import uniffi.pqmsg_android.loadUserProfile
import uniffi.pqmsg_android.openSecondaryDevicePackage

class MainActivity : AppCompatActivity() {
    private lateinit var store: LocalStateStore
    private lateinit var serverInput: EditText
    private lateinit var userInput: EditText
    private lateinit var deviceInput: EditText
    private lateinit var suiteInput: EditText
    private lateinit var pushTokenInput: EditText
    private lateinit var onboardingPassphraseInput: EditText
    private lateinit var onboardingPackageInput: EditText
    private lateinit var onboardingPreviewText: TextView
    private lateinit var presetAliceButton: Button
    private lateinit var presetBobButton: Button
    private lateinit var createProfileButton: Button
    private lateinit var pasteOnboardingButton: Button
    private lateinit var importOnboardingButton: Button
    private lateinit var toggleAdvancedButton: Button
    private lateinit var advancedPanel: LinearLayout
    private lateinit var statusText: TextView
    private lateinit var setupSummaryText: TextView
    private lateinit var cryptoProfileText: TextView
    private lateinit var errorSummaryText: TextView
    private lateinit var errorDetailsText: TextView
    private lateinit var errorToggleButton: Button
    private var errorExpanded = false
    private var advancedVisible = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup)
        store = LocalStateStore(this)

        serverInput = findViewById(R.id.editServer)
        userInput = findViewById(R.id.editUser)
        deviceInput = findViewById(R.id.editDevice)
        suiteInput = findViewById(R.id.editSuite)
        pushTokenInput = findViewById(R.id.editPushToken)
        onboardingPassphraseInput = findViewById(R.id.editOnboardingPassphrase)
        onboardingPackageInput = findViewById(R.id.editOnboardingPackage)
        onboardingPreviewText = findViewById(R.id.textOnboardingPackagePreview)
        presetAliceButton = findViewById(R.id.buttonPresetAlice)
        presetBobButton = findViewById(R.id.buttonPresetBob)
        createProfileButton = findViewById(R.id.buttonCreateProfile)
        pasteOnboardingButton = findViewById(R.id.buttonPasteOnboardingPackage)
        importOnboardingButton = findViewById(R.id.buttonImportOnboardingPackage)
        toggleAdvancedButton = findViewById(R.id.buttonToggleAdvancedSetup)
        advancedPanel = findViewById(R.id.layoutAdvancedSetup)
        statusText = findViewById(R.id.textStatusSetup)
        setupSummaryText = findViewById(R.id.textSetupSummary)
        cryptoProfileText = findViewById(R.id.textCryptoProfile)
        errorSummaryText = findViewById(R.id.textErrorSummarySetup)
        errorDetailsText = findViewById(R.id.textErrorDetailsSetup)
        errorToggleButton = findViewById(R.id.buttonToggleErrorDetailsSetup)

        val setup = store.loadSetup()
        if (hasConsumerProfile(setup)) {
            openHome(finishCurrent = true)
            return
        }

        serverInput.setText(setup.serverUrl)
        userInput.setText(setup.userId)
        deviceInput.setText(setup.deviceId)
        suiteInput.setText(
            if (setup.suiteLabel.isBlank()) {
                MessagingCoordinator.normalizeSuiteLabel("")
            } else {
                MessagingCoordinator.normalizeSuiteLabel(setup.suiteLabel)
            },
        )

        configureInputObservers()
        configureErrorToggle()
        configureAdvancedToggle()

        presetAliceButton.setOnClickListener {
            applyPreset("alice", "bob")
        }

        presetBobButton.setOnClickListener {
            applyPreset("bob", "alice")
        }

        createProfileButton.setOnClickListener {
            lifecycleScope.launch {
                runAction("Create secure profile") {
                    bootstrapProfile()
                }
            }
        }

        pasteOnboardingButton.setOnClickListener {
            pasteOnboardingPackageFromClipboard()
        }

        importOnboardingButton.setOnClickListener {
            confirmImportSecondaryDevicePackage()
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

        refreshSummary()
        refreshOnboardingPackagePreview()
        refreshAdvancedVisibility()
        syncActionAvailability()
    }

    private fun hasConsumerProfile(setup: SetupConfig): Boolean {
        if (setup.userId.isBlank() || setup.serverUrl.isBlank()) {
            return false
        }
        return !store.readKeys(setup.userId).isNullOrBlank()
    }

    private fun configureInputObservers() {
        userInput.doAfterTextChanged { refreshSummary() }
        serverInput.doAfterTextChanged { refreshSummary() }
        suiteInput.doAfterTextChanged { refreshSummary() }
        deviceInput.doAfterTextChanged { refreshSummary() }
        pushTokenInput.doAfterTextChanged { refreshSummary() }
        onboardingPassphraseInput.doAfterTextChanged {
            refreshOnboardingPackagePreview()
            syncActionAvailability()
        }
        onboardingPackageInput.doAfterTextChanged {
            refreshOnboardingPackagePreview()
            syncActionAvailability()
        }
    }

    private fun configureErrorToggle() {
        errorToggleButton.setOnClickListener {
            errorExpanded = !errorExpanded
            refreshErrorDetailsVisibility()
        }
        renderError(null)
    }

    private fun configureAdvancedToggle() {
        toggleAdvancedButton.setOnClickListener {
            advancedVisible = !advancedVisible
            refreshAdvancedVisibility()
        }
    }

    private fun refreshAdvancedVisibility() {
        advancedPanel.visibility = if (advancedVisible) View.VISIBLE else View.GONE
        toggleAdvancedButton.setText(
            if (advancedVisible) {
                R.string.button_hide_advanced_setup
            } else {
                R.string.button_show_advanced_setup
            },
        )
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
        refreshSummary()
    }

    private fun applyPreset(userId: String, peerId: String) {
        userInput.setText(userId)
        deviceInput.setText(MessagingCoordinator.normalizedDeviceId(userId, ""))
        val currentSetup = store.loadSetup()
        store.saveSetup(currentSetup.copy(peerUserId = peerId))
        refreshSummary()
    }

    private fun syncActionAvailability() {
        createProfileButton.isEnabled = userInput.text.toString().trim().isNotBlank()
        importOnboardingButton.isEnabled =
            onboardingPassphraseInput.text.toString().isNotBlank() &&
                onboardingPackageInput.text.toString().trim().isNotBlank()
    }

    private fun refreshSummary() {
        val user = userInput.text.toString().trim()
        val server = serverInput.text.toString().trim()
        setupSummaryText.text = when {
            user.isBlank() ->
                "Choose a username to create this device profile, or import a linked-device package from another trusted device."
            server.isBlank() ->
                "Enter the relay address before creating @$user on this phone."
            else ->
                "Create a secure local profile for @$user on this phone. Advanced relay, device, and push options stay available below if you need them."
        }
    }

    private suspend fun bootstrapProfile(): String {
        val user = userInput.text.toString().trim()
        val server = serverInput.text.toString().trim()
        val suite = MessagingCoordinator.normalizeSuiteLabel(suiteInput.text.toString())
        val deviceId = deviceInput.text.toString().trim()
        val pushToken = pushTokenInput.text.toString().trim()
        require(user.isNotBlank()) { "username is empty" }
        require(server.isNotBlank()) { "server URL is empty" }

        MessagingCoordinator.ensureReady(
            store = store,
            serverUrl = server,
            userId = user,
            suiteLabel = suite,
            deviceId = deviceId,
            pushToken = pushToken,
            onStep = { statusText.text = it },
        )
        openHome(finishCurrent = true)
        return "Secure profile ready for $user"
    }

    private fun requireOpenedOnboardingPackage(): SecondaryDeviceOnboardingPackage {
        val packagePassphrase = onboardingPassphraseInput.text.toString()
        require(packagePassphrase.isNotBlank()) { "onboarding package passphrase is empty" }
        val packageJson = onboardingPackageInput.text.toString().trim()
        require(packageJson.isNotBlank()) { "onboarding package is empty" }
        return openSecondaryDevicePackage(packageJson, packagePassphrase)
    }

    private fun refreshOnboardingPackagePreview() {
        val packagePassphrase = onboardingPassphraseInput.text.toString()
        val packageJson = onboardingPackageInput.text.toString().trim()
        onboardingPreviewText.text = when {
            packagePassphrase.isBlank() || packageJson.isBlank() ->
                getString(R.string.onboarding_package_preview_default)
            else -> runCatching {
                formatLinkedDevicePackagePreview(
                    openSecondaryDevicePackage(packageJson, packagePassphrase),
                )
            }.getOrElse {
                "Linked device package preview unavailable\n${it.message ?: "The package or passphrase is invalid."}"
            }
        }
    }

    private fun confirmImportSecondaryDevicePackage() {
        runCatching {
            val imported = requireOpenedOnboardingPackage()
            val warnings = buildLinkedDeviceImportWarnings(
                currentServerUrl = serverInput.text.toString(),
                currentUserId = userInput.text.toString(),
                currentDeviceId = deviceInput.text.toString(),
                hasExistingLocalStateForImportedUser = !store.readKeys(imported.userId).isNullOrBlank(),
                pkg = imported,
            )
            imported to warnings
        }.onSuccess { (imported, warnings) ->
            AlertDialog.Builder(this)
                .setTitle(R.string.linked_device_import_title)
                .setMessage(buildLinkedDeviceImportConfirmationMessage(imported, warnings))
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.button_import_onboarding_package) { _, _ ->
                    lifecycleScope.launch {
                        runAction("Import linked device") {
                            importSecondaryDevicePackage()
                        }
                    }
                }
                .show()
        }.onFailure {
            renderError(UiErrorMapper.fromThrowable(it, "Inspect linked-device package"))
            statusText.text = "Import linked device failed"
        }
    }

    private suspend fun importSecondaryDevicePackage(): String {
        val imported = requireOpenedOnboardingPackage()
        val profile = loadUserProfile(imported.keysJson)
        val priorPeer = store.loadSetup().peerUserId.ifBlank { "bob" }
        store.wipeUserState(imported.userId)
        store.writeKeys(imported.userId, imported.keysJson)
        store.saveSetup(
            SetupConfig(
                serverUrl = imported.serverUrl,
                userId = imported.userId,
                deviceId = imported.deviceId,
                suiteLabel = MessagingCoordinator.normalizeSuiteLabel(
                    if (profile.suite == uniffi.pqmsg_android.Suite.KYBER768) {
                        "kyber768"
                    } else {
                        "ml-kem-768"
                    },
                ),
                peerUserId = priorPeer,
            ),
        )
        store.saveProgress(imported.userId, SetupProgress().adoptLinkedDevice())
        userInput.setText(imported.userId)
        serverInput.setText(imported.serverUrl)
        deviceInput.setText(imported.deviceId)
        suiteInput.setText(
            MessagingCoordinator.normalizeSuiteLabel(
                if (profile.suite == uniffi.pqmsg_android.Suite.KYBER768) {
                    "kyber768"
                } else {
                    "ml-kem-768"
                },
            ),
        )
        onboardingPackageInput.setText("")
        onboardingPassphraseInput.setText("")
        MessagingCoordinator.ensureReady(
            store = store,
            serverUrl = imported.serverUrl,
            userId = imported.userId,
            suiteLabel = suiteInput.text.toString(),
            deviceId = imported.deviceId,
            onStep = { statusText.text = it },
        )
        openHome(finishCurrent = true)
        return "Linked device imported for ${imported.userId}"
    }

    private fun pasteOnboardingPackageFromClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip
        val itemText = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)
        if (itemText.isNullOrBlank()) {
            statusText.text = "Clipboard does not contain an onboarding package"
            return
        }
        onboardingPackageInput.setText(itemText.toString())
        statusText.text = "Onboarding package pasted"
    }

    private fun openHome(finishCurrent: Boolean = false) {
        startActivity(Intent(this, ConversationsActivity::class.java))
        if (finishCurrent) {
            finish()
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
            errorToggleButton.setText(R.string.button_hide_error_details)
        } else {
            errorDetailsText.visibility = View.GONE
            errorToggleButton.setText(R.string.button_show_error_details)
        }
    }
}
