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
import uniffi.pqmsg_android.buildInboxAuthHeaders

class ContactDiscoveryActivity : AppCompatActivity() {
    private lateinit var store: LocalStateStore
    private lateinit var statusText: TextView
    private lateinit var contactUserIdInput: EditText
    private lateinit var contactAliasInput: EditText
    private lateinit var addContactButton: MaterialButton
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
        contactsList = findViewById(R.id.listContacts)
        emptyText = findViewById(R.id.textContactsEmpty)
        backButton = findViewById(R.id.buttonBackFromContacts)

        addContactButton.setOnClickListener { addContact() }
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
        lifecycleScope.launch {
            runCatching {
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                )
                val response = context.api.listContacts(
                    userId = context.profile.userId,
                    headers = buildInboxAuthHeaders(
                        keysJson = context.keysJson,
                        userId = context.profile.userId,
                        since = 0L,
                    ).toHeaderMap(),
                )
                currentContacts = response.contacts
                renderContacts()
                statusText.text = "${currentContacts.size} contact(s)"
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
                    val alias = contact.alias?.let { " ($it)" } ?: ""
                    val verified = if (contact.verified_by_qr) " ✓" else ""
                    tv.text = "${contact.contact_user_id}$alias$verified"
                    return tv
                }
            }
        }
    }

    private fun addContact() {
        val userId = contactUserIdInput.text.toString().trim()
        if (userId.isBlank()) {
            statusText.text = "Enter a username"
            return
        }
        val alias = contactAliasInput.text.toString().trim().ifBlank { null }
        val setup = store.loadSetup()

        lifecycleScope.launch {
            runCatching {
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                )
                context.api.upsertContact(
                    userId = context.profile.userId,
                    headers = buildInboxAuthHeaders(
                        keysJson = context.keysJson,
                        userId = context.profile.userId,
                        since = 0L,
                    ).toHeaderMap(),
                    request = UpsertContactRequest(
                        contact_user_id = userId,
                        alias = alias,
                        verified_by_qr = null,
                        verified_fingerprint_sha256 = null,
                    ),
                )
                contactUserIdInput.setText("")
                contactAliasInput.setText("")
                statusText.text = "Contact added: $userId"
                loadContacts()
            }.onFailure {
                statusText.text = UiErrorMapper.fromThrowable(it, "Add contact").headline
            }
        }
    }

    private fun showContactActions(contact: ContactListItem) {
        val options = arrayOf("Open Chat", "Remove Contact")
        AlertDialog.Builder(this)
            .setTitle(contact.contact_user_id)
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
                    headers = buildInboxAuthHeaders(
                        keysJson = context.keysJson,
                        userId = context.profile.userId,
                        since = 0L,
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
