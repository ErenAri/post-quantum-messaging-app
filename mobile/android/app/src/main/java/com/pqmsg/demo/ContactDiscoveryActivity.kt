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
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.launch
import uniffi.pqmsg_android.buildContactDiscoveryTicketAuthHeaders
import uniffi.pqmsg_android.buildContactsListAuthHeaders
import uniffi.pqmsg_android.buildContactsRemoveAuthHeaders
import uniffi.pqmsg_android.buildContactsUpsertAuthHeaders

class ContactDiscoveryActivity : AppCompatActivity() {
    private lateinit var store: LocalStateStore
    private lateinit var statusText: TextView
    private lateinit var contactUserIdInput: EditText
    private lateinit var contactAliasInput: EditText
    private lateinit var addContactButton: MaterialButton
    private lateinit var privateDiscoveryCard: View
    private lateinit var discoveryPhonesInput: EditText
    private lateinit var discoveryEmailsInput: EditText
    private lateinit var discoveryQueryInput: EditText
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
            discoveryPhonesInput.setText("")
            discoveryEmailsInput.setText("")
            discoveryQueryInput.setText("")
        }
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

    private suspend fun issueDiscoveryTicket(context: ReadyMessagingContext): ContactDiscoveryTicketResponse {
        val configuredOrigin = context.capabilities.contact_discovery_service_origin?.trim().orEmpty()
        require(configuredOrigin.isNotBlank()) {
            "Private contact discovery service is not configured"
        }
        val response = context.api.issueContactDiscoveryTicket(
            userId = context.profile.userId,
            headers = buildContactDiscoveryTicketAuthHeaders(
                keysJson = context.keysJson,
                userId = context.profile.userId,
            ).toHeaderMap(),
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
                val ticket = issueDiscoveryTicket(context)
                val discoveryApi = ApiClientFactory.createDiscovery(ticket.service_origin)
                val response = discoveryApi.uploadDiscoveryHandles(
                    PrivateDiscoveryHandlesUploadRequest(
                        ticket = ticket.ticket,
                        phone_hashes_sha256 = phoneHashes,
                        email_hashes_sha256 = emailHashes,
                    ),
                )
                statusText.text = getString(
                    R.string.contacts_discovery_uploaded_status,
                    response.uploaded_phone_hashes,
                    response.uploaded_email_hashes,
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
                val ticket = issueDiscoveryTicket(context)
                val discoveryApi = ApiClientFactory.createDiscovery(ticket.service_origin)
                val response = discoveryApi.matchDiscoveryHashes(
                    PrivateDiscoveryMatchRequest(
                        ticket = ticket.ticket,
                        hashes_sha256 = hashes,
                    ),
                )
                if (response.matches.isEmpty()) {
                    discoveryMatchesText.visibility = View.VISIBLE
                    discoveryMatchesText.text = getString(R.string.contacts_discovery_matches_empty)
                } else {
                    discoveryMatchesText.visibility = View.VISIBLE
                    discoveryMatchesText.text = response.matches.joinToString(separator = "\n") {
                        "${it.matched_user_id} [${it.handle_kind}] ${it.hash_sha256}"
                    }
                    if (contactUserIdInput.text.isNullOrBlank()) {
                        contactUserIdInput.setText(response.matches.first().matched_user_id)
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
