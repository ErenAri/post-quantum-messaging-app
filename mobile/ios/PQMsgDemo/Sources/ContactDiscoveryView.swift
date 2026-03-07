import SwiftUI

struct ContactDiscoveryView: View {
    @EnvironmentObject private var appState: AppState
    @State private var contactUserId = ""
    @State private var contactAlias = ""

    var body: some View {
        VStack(spacing: 12) {
            GroupBox("Add Contact") {
                VStack(spacing: 8) {
                    TextField("User ID", text: $contactUserId)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textFieldStyle(.roundedBorder)
                    TextField("Alias (optional)", text: $contactAlias)
                        .textFieldStyle(.roundedBorder)
                    Button("Add Contact") {
                        let uid = contactUserId
                        let alias = contactAlias
                        contactUserId = ""
                        contactAlias = ""
                        Task { await appState.addContact(contactUserId: uid, alias: alias) }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(contactUserId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                .padding(.top, 4)
            }
            .padding(.horizontal)

            if appState.contacts.isEmpty {
                Spacer()
                Text("No contacts yet")
                    .foregroundStyle(.secondary)
                Spacer()
            } else {
                List {
                    ForEach(appState.contacts) { contact in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(contact.contact_user_id)
                                    .font(.headline)
                                if let alias = contact.alias, !alias.isEmpty {
                                    Text(alias)
                                        .font(.subheadline)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            if contact.verified {
                                Image(systemName: "checkmark.shield.fill")
                                    .foregroundStyle(.green)
                            }
                        }
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                Task { await appState.removeContact(contactUserId: contact.contact_user_id) }
                            } label: {
                                Label("Remove", systemImage: "trash")
                            }
                        }
                        .swipeActions(edge: .leading) {
                            Button {
                                appState.openConversation(peerUserId: contact.contact_user_id)
                            } label: {
                                Label("Chat", systemImage: "message")
                            }
                            .tint(.blue)
                        }
                    }
                }
                .listStyle(.plain)
            }

            if !appState.errorLine.isEmpty {
                Text(appState.errorLine)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }
        }
        .navigationTitle("Contacts")
        .task {
            await appState.loadContacts()
        }
    }
}
