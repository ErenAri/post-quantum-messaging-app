package com.pqmsg.demo

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import uniffi.pqmsg_android.PqmsgAndroidException
import uniffi.pqmsg_android.Suite
import uniffi.pqmsg_android.buildPublishPrekeysPayload
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
    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup)
        store = LocalStateStore(this)
        serverInput = findViewById(R.id.editServer)
        userInput = findViewById(R.id.editUser)
        deviceInput = findViewById(R.id.editDevice)
        suiteInput = findViewById(R.id.editSuite)
        peerInput = findViewById(R.id.editPeer)
        statusText = findViewById(R.id.textStatusSetup)

        val setup = store.loadSetup()
        serverInput.setText(setup.serverUrl)
        userInput.setText(setup.userId)
        deviceInput.setText(setup.deviceId)
        suiteInput.setText(setup.suiteLabel)
        peerInput.setText(setup.peerUserId)

        findViewById<Button>(R.id.buttonGenerate).setOnClickListener {
            lifecycleScope.launch {
                runCatching {
                    val user = userInput.text.toString().trim()
                    val device = normalizedDeviceId(user, deviceInput.text.toString().trim())
                    val suite = parseSuite(suiteInput.text.toString())
                    val keysJson = generateIdentityKeys(user, device, suite, 16u)
                    store.writeKeys(user, keysJson)
                    saveSetup()
                    val profile = loadUserProfile(keysJson)
                    "generated keys for ${profile.userId} (${profile.deviceId})"
                }.onSuccess {
                    statusText.text = it
                }.onFailure {
                    statusText.text = formatError(it)
                }
            }
        }

        findViewById<Button>(R.id.buttonRegister).setOnClickListener {
            lifecycleScope.launch {
                runCatching {
                    val user = userInput.text.toString().trim()
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
                    "registered ${payload.userId}"
                }.onSuccess {
                    statusText.text = it
                }.onFailure {
                    statusText.text = formatError(it)
                }
            }
        }

        findViewById<Button>(R.id.buttonPublish).setOnClickListener {
            lifecycleScope.launch {
                runCatching {
                    val user = userInput.text.toString().trim()
                    val keysJson = requireKeys(user)
                    val payload = buildPublishPrekeysPayload(keysJson)
                    val api = ApiClientFactory.create(serverInput.text.toString())
                    api.publishPrekeys(
                        user,
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
                    "published prekeys for $user"
                }.onSuccess {
                    statusText.text = it
                }.onFailure {
                    statusText.text = formatError(it)
                }
            }
        }

        findViewById<Button>(R.id.buttonOpenChat).setOnClickListener {
            saveSetup()
            val intent = Intent(this, ChatActivity::class.java).apply {
                putExtra("server", serverInput.text.toString().trim())
                putExtra("user", userInput.text.toString().trim())
                putExtra("peer", peerInput.text.toString().trim())
            }
            startActivity(intent)
        }
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

    private fun formatError(error: Throwable): String {
        return when (error) {
            is PqmsgAndroidException.InvalidInput -> "invalid input: ${error.message}"
            is PqmsgAndroidException.OperationFailed -> "operation failed: ${error.message}"
            else -> error.message ?: error.javaClass.simpleName
        }
    }
}
