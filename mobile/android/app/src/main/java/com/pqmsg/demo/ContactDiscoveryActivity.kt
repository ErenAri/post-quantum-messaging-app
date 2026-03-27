package com.pqmsg.demo

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.launch
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import uniffi.pqmsg_android.buildContactDiscoveryTicketAuthHeaders
import uniffi.pqmsg_android.buildContactsListAuthHeaders
import uniffi.pqmsg_android.buildContactsRemoveAuthHeaders
import uniffi.pqmsg_android.buildContactsUpsertAuthHeaders
import uniffi.pqmsg_android.contactDiscoveryPrepareBlindRequest
import uniffi.pqmsg_android.contactDiscoveryVerifyAndFinalizeTokens
import uniffi.pqmsg_android.verifyContactDiscoveryManifest

data class ContactDiscoveryBlindRequestResult(
    val blinded_elements_base64: List<String>,
    val blinding_scalars_base64: List<String>,
)

private data class VerifiedContactDiscoveryManifest(
    val manifest: ContactDiscoveryManifestResponse,
    val continuityStatus: String,
)

class ContactDiscoveryActivity : AppCompatActivity() {
    private val gson = Gson()
    private val secureRandom = SecureRandom()
    private lateinit var store: LocalStateStore
    private lateinit var statusText: TextView
    private lateinit var contactUserIdInput: EditText
    private lateinit var contactAliasInput: EditText
    private lateinit var addContactButton: MaterialButton
    private lateinit var privateDiscoveryCard: View
    private lateinit var discoveryPhonesInput: EditText
    private lateinit var discoveryEmailsInput: EditText
    private lateinit var discoveryQueryInput: EditText
    private lateinit var discoveryManifestText: TextView
    private lateinit var uploadDiscoveryButton: MaterialButton
    private lateinit var searchDiscoveryButton: MaterialButton
    private lateinit var discoveryMatchesText: TextView
    private lateinit var contactsList: ListView
    private lateinit var emptyText: TextView
    private lateinit var backButton: MaterialButton
    private var currentContacts: List<ContactListItem> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = LocalStateStore(this)
        setContentView(R.layout.activity_contact_discovery)

        statusText = findViewById(R.id.textDiscoveryStatus)
        contactUserIdInput = findViewById(R.id.editContactUserId)
        contactAliasInput = findViewById(R.id.editContactAlias)
        addContactButton = findViewById(R.id.buttonAddContact)
        privateDiscoveryCard = findViewById(R.id.cardPrivateDiscovery)
        discoveryPhonesInput = findViewById(R.id.editDiscoveryPhones)
        discoveryEmailsInput = findViewById(R.id.editDiscoveryEmails)
        discoveryQueryInput = findViewById(R.id.editDiscoveryQuery)
        discoveryManifestText = findViewById(R.id.textDiscoveryManifest)
        uploadDiscoveryButton = findViewById(R.id.buttonUploadDiscoveryHandles)
        searchDiscoveryButton = findViewById(R.id.buttonSearchDiscovery)
        discoveryMatchesText = findViewById(R.id.textDiscoveryMatches)
        contactsList = findViewById(R.id.listContacts)
        emptyText = findViewById(R.id.textContactsEmpty)
        backButton = findViewById(R.id.buttonBackFromContacts)

        addContactButton.setOnClickListener { addContact() }
        uploadDiscoveryButton.setOnClickListener { uploadPrivateDiscoveryHandles() }
        searchDiscoveryButton.setOnClickListener { matchPrivateDiscoveryHashes() }
        backButton.setOnClickListener { finish() }

        contactsList.setOnItemClickListener { _, _, position, _ ->
            val contact = currentContacts.getOrNull(position) ?: return@setOnItemClickListener
            showContactActions(contact)
        }

        loadContacts()
    }

    override fun onResume() {
        super.onResume()
        loadContacts()
    }

    private fun loadContacts() {
        val setup = store.loadSetup()
        if (setup.userId.isBlank() || setup.serverUrl.isBlank()) {
            statusText.text = "Not signed in"
            return
        }
        statusText.text = getString(R.string.contacts_manual_only_notice)
        lifecycleScope.launch {
            runCatching {
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                )
                setPrivateDiscoveryEnabled(
                    enabled = context.capabilities.contact_discovery_mode == "private_service" &&
                        context.capabilities.contact_discovery_supported,
                )
                discoveryManifestText.text = if (
                    context.capabilities.contact_discovery_mode == "private_service" &&
                    context.capabilities.contact_discovery_supported
                ) {
                    renderDiscoveryManifestSummary(context)
                } else {
                    getString(R.string.contacts_private_manifest_unavailable)
                }
                val response = context.api.listContacts(
                    userId = context.profile.userId,
                    headers = buildContactsListAuthHeaders(
                        keysJson = context.keysJson,
                        userId = context.profile.userId,
                    ).toHeaderMap(),
                )
                currentContacts = response.contacts
                renderContacts()
                statusText.text = if (
                    context.capabilities.contact_discovery_mode == "private_service" &&
                    context.capabilities.contact_discovery_supported
                ) {
                    getString(R.string.contacts_private_service_status, currentContacts.size)
                } else {
                    getString(R.string.contacts_manual_status, currentContacts.size)
                }
            }.onFailure {
                statusText.text = UiErrorMapper.fromThrowable(it, "Load contacts").headline
            }
        }
    }

    private fun renderContacts() {
        if (currentContacts.isEmpty()) {
            contactsList.visibility = View.GONE
            emptyText.visibility = View.VISIBLE
        } else {
            contactsList.visibility = View.VISIBLE
            emptyText.visibility = View.GONE
            contactsList.adapter = object : BaseAdapter() {
                override fun getCount() = currentContacts.size
                override fun getItem(position: Int) = currentContacts[position]
                override fun getItemId(position: Int) = position.toLong()
                override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                    val tv = (convertView as? TextView) ?: TextView(this@ContactDiscoveryActivity).apply {
                        setPadding(16, 12, 16, 12)
                        textSize = 14f
                    }
                    val contact = currentContacts[position]
                    val verified = if (contact.verified_by_qr) " ✓" else ""
                    val primary = contactPrimaryLabel(contact)
                    val secondary = contactSecondaryLabel(contact)
                    tv.text = if (secondary.isNullOrBlank()) {
                        "$primary$verified"
                    } else {
                        "$primary$verified\n$secondary"
                    }
                    return tv
                }
            }
        }
    }

    private fun setPrivateDiscoveryEnabled(enabled: Boolean) {
        privateDiscoveryCard.visibility = if (enabled) View.VISIBLE else View.GONE
        if (!enabled) {
            discoveryMatchesText.visibility = View.GONE
            discoveryMatchesText.text = ""
            discoveryManifestText.text = getString(R.string.contacts_private_manifest_unavailable)
            discoveryPhonesInput.setText("")
            discoveryEmailsInput.setText("")
            discoveryQueryInput.setText("")
        }
    }

    private suspend fun renderDiscoveryManifestSummary(
        context: ReadyMessagingContext,
    ): String {
        val verified = loadVerifiedDiscoveryManifest(context)
        val manifest = verified.manifest
        val issuerMatches =
            manifest.ticket_issuer_ed25519_pub == context.capabilities.contact_discovery_ticket_issuer_ed25519_pub
        val summary = if (issuerMatches) {
            getString(
                R.string.contacts_private_manifest_verified,
                manifest.lookup_protocol,
                manifest.privacy_mode,
                manifest.attestation_mode,
            )
        } else {
            getString(
                R.string.contacts_private_manifest_mismatch,
                manifest.lookup_protocol,
                manifest.privacy_mode,
                manifest.attestation_mode,
            )
        }
        val manifestDetails =
            buildList {
                add(getString(R.string.contacts_private_manifest_continuity, verified.continuityStatus))
                if (!manifest.attestation_verifier.isNullOrBlank()) {
                    add(
                        getString(
                            R.string.contacts_private_manifest_attestation_verifier,
                            manifest.attestation_verifier,
                        ),
                    )
                }
                if (!manifest.enclave_measurement_hex.isNullOrBlank()) {
                    add(
                        getString(
                            R.string.contacts_private_manifest_measurement,
                            manifest.enclave_measurement_hex,
                        ),
                    )
                }
                if (!manifest.attestation_pcrs_sha384.isNullOrEmpty()) {
                    add(
                        "Attestation PCRs: " +
                            manifest.attestation_pcrs_sha384
                                .toSortedMap()
                                .entries
                                .joinToString(", ") { (key, value) -> "$key=$value" },
                    )
                }
                add("Host release: ${manifest.host_release_id}")
                add("Enclave release: ${manifest.enclave_release_id}")
            }
        return "$summary\n${manifestDetails.joinToString("\n")}"
    }

    private suspend fun loadVerifiedDiscoveryManifest(
        context: ReadyMessagingContext,
    ): VerifiedContactDiscoveryManifest {
        val capabilities = context.capabilities
        val serviceOrigin = capabilities.contact_discovery_service_origin?.trim().orEmpty()
        require(serviceOrigin.isNotBlank()) {
            "Private contact discovery service is not configured"
        }
        val normalizedServiceOrigin = ApiClientFactory.normalizeBaseUrl(serviceOrigin)
        val manifest = ApiClientFactory.createDiscovery(serviceOrigin).getManifest()
        require(
            manifest.ticket_issuer_ed25519_pub == capabilities.contact_discovery_ticket_issuer_ed25519_pub,
        ) {
            "Contact discovery manifest ticket issuer mismatch"
        }
        require(
            manifest.manifest_issuer_ed25519_pub ==
                capabilities.contact_discovery_manifest_issuer_ed25519_pub,
        ) {
            "Contact discovery manifest issuer mismatch"
        }
        val attestationContractFieldsPresent =
            listOf(
                !capabilities.contact_discovery_attestation_verifier.isNullOrBlank(),
                !capabilities.contact_discovery_expected_measurement_hex.isNullOrBlank(),
                !capabilities.contact_discovery_attestation_document_sha256.isNullOrBlank(),
                capabilities.contact_discovery_attestation_max_age_seconds != null,
            )
        require(
            attestationContractFieldsPresent.none { it } || attestationContractFieldsPresent.all { it },
        ) {
            "Private discovery attestation contract is incomplete"
        }
        verifyContactDiscoveryManifest(
            gson.toJson(manifest),
            capabilities.contact_discovery_ticket_issuer_ed25519_pub,
            capabilities.contact_discovery_manifest_issuer_ed25519_pub.orEmpty(),
            capabilities.contact_discovery_attestation_verifier.orEmpty(),
            capabilities.contact_discovery_expected_measurement_hex.orEmpty(),
            gson.toJson(capabilities.contact_discovery_expected_pcrs_sha384),
            capabilities.contact_discovery_attestation_document_sha256.orEmpty(),
        )
        require(
            !capabilities.contact_discovery_manifest_issuer_ed25519_pub.isNullOrBlank(),
        ) {
            "Contact discovery manifest issuer key is unavailable"
        }
        require(
            manifest.lookup_protocol == "attested_enclave_voprf_directory_v1" &&
                manifest.privacy_mode == "enclave_backed_private_discovery_v1" &&
                manifest.directory_backend == "attested_enclave_directory_v1" &&
                manifest.host_enclave_protocol_version == 1 &&
                manifest.host_release_id.isNotBlank() &&
                manifest.enclave_release_id.isNotBlank() &&
                manifest.match_result_format == "contact_invite_token" &&
                manifest.oprf_suite == "ristretto255-sha512-v1" &&
                manifest.evaluation_proof_mode == "dleq_per_element_v1" &&
                manifest.oprf_public_key_ristretto255.isNotBlank() &&
                manifest.attestation_mode == "attested_enclave_v1" &&
                !manifest.attestation_verifier.isNullOrBlank() &&
                !manifest.enclave_measurement_hex.isNullOrBlank() &&
                !manifest.attestation_document_format.isNullOrBlank() &&
                !manifest.attestation_document_sha256.isNullOrBlank() &&
                !manifest.attestation_challenge_mode.isNullOrBlank(),
        ) {
            "Unsupported contact discovery manifest"
        }
        require(
            manifest.attestation_document_sha256.isNullOrBlank() ||
                manifest.attestation_challenge_mode == "nonce_b64_required_v1",
        ) {
            "Unsupported contact discovery attestation challenge mode"
        }
        require(
            manifest.directory_backend == capabilities.contact_discovery_directory_backend &&
                manifest.host_enclave_protocol_version ==
                capabilities.contact_discovery_host_enclave_protocol_version &&
                manifest.host_release_id == capabilities.contact_discovery_host_release_id &&
                manifest.enclave_release_id == capabilities.contact_discovery_enclave_release_id &&
                contactDiscoveryManifestContractSha256Hex(manifest) ==
                capabilities.contact_discovery_expected_manifest_contract_sha256,
        ) {
            "Contact discovery backend contract mismatch"
        }
        if (!manifest.attestation_document_sha256.isNullOrBlank()) {
            val challengeNonce = ByteArray(16).also(secureRandom::nextBytes)
            val challengeNonceBase64 = Base64.getEncoder().encodeToString(challengeNonce)
            val attestation =
                ApiClientFactory
                    .createDiscovery(serviceOrigin)
                    .getAttestation(challengeNonceBase64)
            verifyContactDiscoveryAttestationDocument(
                response = attestation,
                expectedAttestationMode = manifest.attestation_mode,
                expectedVerifier = manifest.attestation_verifier.orEmpty(),
                expectedMeasurementHex = manifest.enclave_measurement_hex.orEmpty(),
                expectedPcrsSha384 = manifest.attestation_pcrs_sha384,
                expectedManifestIssuerEd25519Pub = manifest.manifest_issuer_ed25519_pub,
                expectedChallengeNonceBase64 = challengeNonceBase64,
                expectedManifestContractSha256 = contactDiscoveryManifestContractSha256Hex(manifest),
                expectedHostReleaseId = manifest.host_release_id,
                expectedEnclaveReleaseId = manifest.enclave_release_id,
                expectedOprfPublicKeyRistretto255 = manifest.oprf_public_key_ristretto255,
                expectedDocumentSha256 = manifest.attestation_document_sha256.orEmpty(),
                expectedMaxAgeSeconds = capabilities.contact_discovery_attestation_max_age_seconds ?: 0,
            )
        }
        val checkpoint = buildContactDiscoveryManifestCheckpoint(
            serviceOrigin = normalizedServiceOrigin,
            manifest = manifest,
            observedAt = Instant.now().toString(),
        )
        val previousCheckpoint = store.readContactDiscoveryCheckpoint(
            context.serverUrl,
            context.profile.userId,
        )?.let { checkpointJson ->
            runCatching {
                gson.fromJson(checkpointJson, ContactDiscoveryManifestCheckpoint::class.java)
            }.getOrNull()
        }
        val changedFields =
            if (previousCheckpoint == null) {
                emptyList()
            } else {
                diffContactDiscoveryManifestCheckpoint(previousCheckpoint, checkpoint)
            }
        require(changedFields.isEmpty()) {
            "Contact discovery manifest continuity changed: ${changedFields.joinToString(", ")}"
        }
        store.writeContactDiscoveryCheckpoint(
            context.serverUrl,
            context.profile.userId,
            gson.toJson(checkpoint),
        )
        return VerifiedContactDiscoveryManifest(
            manifest = manifest,
            continuityStatus = if (previousCheckpoint == null) {
                getString(R.string.contacts_private_manifest_continuity_saved)
            } else {
                getString(R.string.contacts_private_manifest_continuity_pinned)
            },
        )
    }

    private fun normalizeDiscoveryHashes(rawValue: String): List<String> {
        val values = rawValue
            .lineSequence()
            .map { it.trim().lowercase() }
            .filter { it.isNotBlank() }
            .toList()
        require(values.size <= 2048) { "At most 2048 hashes are allowed per request" }
        require(values.all { value -> value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' } }) {
            "Discovery values must be 64-character SHA-256 hex strings"
        }
        return values.distinct().sorted()
    }

    private fun prepareDiscoveryBlindRequest(hashes: List<String>): ContactDiscoveryBlindRequestResult {
        val json = contactDiscoveryPrepareBlindRequest(gson.toJson(hashes))
        return gson.fromJson(json, ContactDiscoveryBlindRequestResult::class.java)
    }

    private fun verifyAndFinalizeDiscoveryTokens(
        blindedElementsBase64: List<String>,
        blindingScalarsBase64: List<String>,
        evaluatedResponse: PrivateDiscoveryEvaluateResponse,
        expectedOprfPublicKeyRistretto255: String,
    ): List<String> {
        val json = contactDiscoveryVerifyAndFinalizeTokens(
            gson.toJson(blindedElementsBase64),
            gson.toJson(blindingScalarsBase64),
            gson.toJson(evaluatedResponse),
            expectedOprfPublicKeyRistretto255,
        )
        return gson.fromJson(
            json,
            object : TypeToken<List<String>>() {}.type,
        )
    }

    private fun requireDiscoveryServiceContract(
        expectedManifestContractSha256: String,
        observedManifestContractSha256: String,
        operationLabel: String,
    ) {
        require(observedManifestContractSha256 == expectedManifestContractSha256) {
            "Contact discovery $operationLabel contract mismatch"
        }
    }

    private fun requireDiscoveryServiceTicketNonce(
        expectedTicketNonce: String,
        observedTicketNonce: String,
        operationLabel: String,
    ) {
        require(observedTicketNonce == expectedTicketNonce) {
            "Contact discovery $operationLabel ticket mismatch"
        }
    }

    private suspend fun issueDiscoveryTicket(
        context: ReadyMessagingContext,
        purpose: String,
    ): ContactDiscoveryTicketResponse {
        val configuredOrigin = context.capabilities.contact_discovery_service_origin?.trim().orEmpty()
        require(configuredOrigin.isNotBlank()) {
            "Private contact discovery service is not configured"
        }
        val response = context.api.issueContactDiscoveryTicket(
            userId = context.profile.userId,
            headers = buildContactDiscoveryTicketAuthHeaders(
                keysJson = context.keysJson,
                userId = context.profile.userId,
                purpose = purpose,
            ).toHeaderMap(),
            request = ContactDiscoveryTicketRequest(purpose = purpose),
        )
        require(
            ApiClientFactory.normalizeBaseUrl(response.service_origin) ==
                ApiClientFactory.normalizeBaseUrl(configuredOrigin),
        ) {
            "Contact discovery service origin mismatch"
        }
        return response
    }

    private fun uploadPrivateDiscoveryHandles() {
        val setup = store.loadSetup()
        lifecycleScope.launch {
            runCatching {
                val phoneHashes = normalizeDiscoveryHashes(discoveryPhonesInput.text.toString())
                val emailHashes = normalizeDiscoveryHashes(discoveryEmailsInput.text.toString())
                require(phoneHashes.isNotEmpty() || emailHashes.isNotEmpty()) {
                    "Enter at least one phone or email hash"
                }
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                )
                require(
                    context.capabilities.contact_discovery_mode == "private_service" &&
                        context.capabilities.contact_discovery_supported,
                ) {
                    "Private contact discovery is unavailable for this profile"
                }
                val manifest = loadVerifiedDiscoveryManifest(context).manifest
                val manifestContractSha256 = contactDiscoveryManifestContractSha256Hex(manifest)
                val ticket = issueDiscoveryTicket(context, "upload")
                val discoveryApi = ApiClientFactory.createDiscovery(ticket.service_origin)
                val phonePrepared = prepareDiscoveryBlindRequest(phoneHashes)
                val emailPrepared = prepareDiscoveryBlindRequest(emailHashes)
                val phoneEvaluated =
                    if (phonePrepared.blinded_elements_base64.isEmpty()) {
                        PrivateDiscoveryEvaluateResponse(
                            user_id = context.profile.userId,
                            device_id = context.profile.deviceId,
                            ticket_nonce = ticket.ticket_nonce,
                            manifest_contract_sha256 = manifestContractSha256,
                            evaluation_proof_mode = manifest.evaluation_proof_mode,
                            evaluated_elements_base64 = emptyList(),
                            dleq_proofs = emptyList(),
                            evaluated_at = Instant.now().toString(),
                        )
                    } else {
                        discoveryApi.evaluateDiscoveryElements(
                            PrivateDiscoveryEvaluateRequest(
                                ticket = ticket.ticket,
                                blinded_elements_base64 = phonePrepared.blinded_elements_base64,
                            ),
                        )
                    }
                val emailEvaluated =
                    if (emailPrepared.blinded_elements_base64.isEmpty()) {
                        PrivateDiscoveryEvaluateResponse(
                            user_id = context.profile.userId,
                            device_id = context.profile.deviceId,
                            ticket_nonce = ticket.ticket_nonce,
                            manifest_contract_sha256 = manifestContractSha256,
                            evaluation_proof_mode = manifest.evaluation_proof_mode,
                            evaluated_elements_base64 = emptyList(),
                            dleq_proofs = emptyList(),
                            evaluated_at = Instant.now().toString(),
                        )
                    } else {
                        discoveryApi.evaluateDiscoveryElements(
                            PrivateDiscoveryEvaluateRequest(
                                ticket = ticket.ticket,
                                blinded_elements_base64 = emailPrepared.blinded_elements_base64,
                            ),
                        )
                    }
                requireDiscoveryServiceContract(
                    manifestContractSha256,
                    phoneEvaluated.manifest_contract_sha256,
                    "evaluate",
                )
                requireDiscoveryServiceTicketNonce(
                    ticket.ticket_nonce,
                    phoneEvaluated.ticket_nonce,
                    "evaluate",
                )
                requireDiscoveryServiceContract(
                    manifestContractSha256,
                    emailEvaluated.manifest_contract_sha256,
                    "evaluate",
                )
                requireDiscoveryServiceTicketNonce(
                    ticket.ticket_nonce,
                    emailEvaluated.ticket_nonce,
                    "evaluate",
                )
                val phoneTokens = verifyAndFinalizeDiscoveryTokens(
                    phonePrepared.blinded_elements_base64,
                    phonePrepared.blinding_scalars_base64,
                    phoneEvaluated,
                    manifest.oprf_public_key_ristretto255,
                )
                val emailTokens = verifyAndFinalizeDiscoveryTokens(
                    emailPrepared.blinded_elements_base64,
                    emailPrepared.blinding_scalars_base64,
                    emailEvaluated,
                    manifest.oprf_public_key_ristretto255,
                )
                val response = discoveryApi.uploadDiscoveryHandles(
                    PrivateDiscoveryHandlesUploadRequest(
                        ticket = ticket.ticket,
                        phone_tokens_sha256 = phoneTokens,
                        email_tokens_sha256 = emailTokens,
                    ),
                )
                requireDiscoveryServiceContract(
                    manifestContractSha256,
                    response.manifest_contract_sha256,
                    "upload",
                )
                requireDiscoveryServiceTicketNonce(
                    ticket.ticket_nonce,
                    response.ticket_nonce,
                    "upload",
                )
                statusText.text = getString(
                    R.string.contacts_discovery_uploaded_status,
                    response.uploaded_phone_tokens,
                    response.uploaded_email_tokens,
                )
            }.onFailure {
                statusText.text = UiErrorMapper.fromThrowable(it, "Upload discovery handles").headline
            }
        }
    }

    private fun matchPrivateDiscoveryHashes() {
        val setup = store.loadSetup()
        lifecycleScope.launch {
            runCatching {
                val hashes = normalizeDiscoveryHashes(discoveryQueryInput.text.toString())
                require(hashes.isNotEmpty()) { "Enter at least one query hash" }
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                )
                require(
                    context.capabilities.contact_discovery_mode == "private_service" &&
                        context.capabilities.contact_discovery_supported,
                ) {
                    "Private contact discovery is unavailable for this profile"
                }
                val manifest = loadVerifiedDiscoveryManifest(context).manifest
                val manifestContractSha256 = contactDiscoveryManifestContractSha256Hex(manifest)
                val ticket = issueDiscoveryTicket(context, "match")
                val discoveryApi = ApiClientFactory.createDiscovery(ticket.service_origin)
                val prepared = prepareDiscoveryBlindRequest(hashes)
                val evaluated = discoveryApi.evaluateDiscoveryElements(
                    PrivateDiscoveryEvaluateRequest(
                        ticket = ticket.ticket,
                        blinded_elements_base64 = prepared.blinded_elements_base64,
                    ),
                )
                requireDiscoveryServiceContract(
                    manifestContractSha256,
                    evaluated.manifest_contract_sha256,
                    "evaluate",
                )
                requireDiscoveryServiceTicketNonce(
                    ticket.ticket_nonce,
                    evaluated.ticket_nonce,
                    "evaluate",
                )
                val tokens = verifyAndFinalizeDiscoveryTokens(
                    prepared.blinded_elements_base64,
                    prepared.blinding_scalars_base64,
                    evaluated,
                    manifest.oprf_public_key_ristretto255,
                )
                val hashByToken = tokens.zip(hashes).toMap()
                val response = discoveryApi.matchDiscoveryHashes(
                    PrivateDiscoveryMatchRequest(
                        ticket = ticket.ticket,
                        tokens_sha256 = tokens,
                    ),
                )
                requireDiscoveryServiceContract(
                    manifestContractSha256,
                    response.manifest_contract_sha256,
                    "match",
                )
                requireDiscoveryServiceTicketNonce(
                    ticket.ticket_nonce,
                    response.ticket_nonce,
                    "match",
                )
                if (response.matches.isEmpty()) {
                    discoveryMatchesText.visibility = View.VISIBLE
                    discoveryMatchesText.text = getString(R.string.contacts_discovery_matches_empty)
                } else {
                    discoveryMatchesText.visibility = View.VISIBLE
                    discoveryMatchesText.text = response.matches.joinToString(separator = "\n") {
                        "invite:${it.contact_invite_token.takeLast(8)} [${it.handle_kind}] ${hashByToken[it.token_sha256] ?: it.token_sha256}"
                    }
                    if (contactUserIdInput.text.isNullOrBlank()) {
                        contactUserIdInput.setText(
                            MessagingCoordinator.buildInviteLink(
                                setup.serverUrl,
                                response.matches.first().contact_invite_token,
                            ),
                        )
                    }
                }
                statusText.text = getString(
                    R.string.contacts_discovery_matches_status,
                    response.matches.size,
                )
            }.onFailure {
                statusText.text = UiErrorMapper.fromThrowable(it, "Search discovery").headline
            }
        }
    }

    private fun addContact() {
        val rawTarget = contactUserIdInput.text.toString().trim()
        if (rawTarget.isBlank()) {
            statusText.text = "Enter an @username or invite link"
            return
        }
        val alias = contactAliasInput.text.toString().trim().ifBlank { null }
        val setup = store.loadSetup()

        lifecycleScope.launch {
            runCatching {
                val target = MessagingCoordinator.parseComposeTarget(rawTarget, setup.serverUrl)
                require(
                    ApiClientFactory.normalizeBaseUrl(target.serverUrl) ==
                        ApiClientFactory.normalizeBaseUrl(setup.serverUrl),
                ) {
                    "Contacts can only be added for the active server profile"
                }
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = target.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                )
                val validatedBundle = when {
                    !target.inviteToken.isNullOrBlank() -> context.api.getContactInviteBundle(
                        target.inviteToken.trim(),
                    )
                    !target.username.isNullOrBlank() -> context.api.getUsernameBundle(
                        target.username.trim(),
                    )
                    else -> null
                }
                val resolvedPeerUserId = validatedBundle?.user_id?.trim()?.removePrefix("@")
                    ?.takeIf { it.isNotBlank() }
                    ?: MessagingCoordinator.resolvePeerUserId(
                        context.api,
                        target,
                    )
                if (validatedBundle == null) {
                    context.api.getBundle(resolvedPeerUserId)
                }
                context.api.upsertContact(
                    userId = context.profile.userId,
                    headers = buildContactsUpsertAuthHeaders(
                        keysJson = context.keysJson,
                        userId = context.profile.userId,
                        contactUserId = resolvedPeerUserId,
                        alias = alias ?: resolvedPeerUserId,
                        verifiedByQr = false,
                        verifiedFingerprintSha256 = null,
                    ).toHeaderMap(),
                    request = UpsertContactRequest(
                        contact_user_id = resolvedPeerUserId,
                        alias = alias,
                        verified_by_qr = null,
                        verified_fingerprint_sha256 = null,
                    ),
                )
                contactUserIdInput.setText("")
                contactAliasInput.setText("")
                statusText.text = getString(R.string.contacts_added_status, resolvedPeerUserId)
                loadContacts()
            }.onFailure {
                statusText.text = UiErrorMapper.fromThrowable(it, "Add contact").headline
            }
        }
    }

    private fun showContactActions(contact: ContactListItem) {
        val options = arrayOf("Open Chat", "Remove Contact")
        AlertDialog.Builder(this)
            .setTitle(contactPrimaryLabel(contact))
            .setMessage(contactSecondaryLabel(contact))
            .setItems(options) { _, which ->
                when (which) {
                    0 -> {
                        store.markPeerAccepted(store.loadSetup().userId, contact.contact_user_id)
                        startActivity(
                            Intent(this, ChatActivity::class.java).apply {
                                putExtra("peer", contact.contact_user_id)
                            },
                        )
                    }
                    1 -> removeContact(contact.contact_user_id)
                }
            }
            .show()
    }

    private fun contactPrimaryLabel(contact: ContactListItem): String {
        return contact.alias?.trim()?.takeIf { it.isNotBlank() } ?: contactHandle(contact)
    }

    private fun contactSecondaryLabel(contact: ContactListItem): String? {
        val handle = contactHandle(contact)
        return if (contactPrimaryLabel(contact) == handle) null else handle
    }

    private fun contactHandle(contact: ContactListItem): String {
        val username = contact.username?.trim()?.removePrefix("@").orEmpty()
        return if (username.isNotBlank()) "@$username" else contact.contact_user_id
    }

    private fun removeContact(contactUserId: String) {
        val setup = store.loadSetup()
        lifecycleScope.launch {
            runCatching {
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                )
                context.api.removeContact(
                    userId = context.profile.userId,
                    headers = buildContactsRemoveAuthHeaders(
                        keysJson = context.keysJson,
                        userId = context.profile.userId,
                        contactUserId = contactUserId,
                    ).toHeaderMap(),
                    request = RemoveContactRequest(contact_user_id = contactUserId),
                )
                statusText.text = "Removed: $contactUserId"
                loadContacts()
            }.onFailure {
                statusText.text = UiErrorMapper.fromThrowable(it, "Remove contact").headline
            }
        }
    }
}

