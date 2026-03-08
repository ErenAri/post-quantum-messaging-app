import SwiftUI

struct ConversationsView: View {
    @EnvironmentObject private var appState: AppState
    @State private var showingChat = false
    @State private var showingGroupChat = false
    @State private var showingCreateGroup = false
    @State private var selectedGroup: GroupSummary?
    @State private var newGroupName = ""
    @State private var newGroupMembers = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                HStack {
                    TextField(
                        "Peer User ID",
                        text: Binding(
                            get: { appState.setup.peerUserId },
                            set: { appState.setPeerUserId($0) }
                        )
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)

                    Button("Open") {
                        appState.openConversation(peerUserId: appState.setup.peerUserId)
                        showingChat = true
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!appState.progress.canOpenConversations())
                }
                .padding(.horizontal)
                .padding(.top, 8)

                HStack {
                    Button("Refresh") {
                        Task { await appState.syncGroups() }
                    }
                    .buttonStyle(.bordered)

                    NavigationLink("Contacts") {
                        ContactDiscoveryView()
                            .environmentObject(appState)
                    }
                    .buttonStyle(.bordered)

                    Button("New Group") {
                        showingCreateGroup = true
                    }
                    .buttonStyle(.bordered)

                    Spacer()
                    Text(appState.statusLine)
                        .font(.caption)
                }
                .padding(.horizontal)

                if !appState.groups.isEmpty {
                    Section {
                        ForEach(appState.groups) { group in
                            Button {
                                selectedGroup = group
                                showingGroupChat = true
                            } label: {
                                HStack {
                                    Image(systemName: "person.3")
                                        .foregroundStyle(.blue)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(group.displayName)
                                            .font(.headline)
                                        Text(group.lastPreview)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                    if group.unreadCount > 0 {
                                        Text("\(group.unreadCount)")
                                            .font(.caption2)
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(Color.red.opacity(0.2))
                                            .clipShape(Capsule())
                                    }
                                }
                            }
                            .padding(.horizontal)
                        }
                    } header: {
                        Text("Groups")
                            .font(.caption)
                            .padding(.horizontal)
                    }
                }

                if appState.conversations.isEmpty && appState.groups.isEmpty {
                    Spacer()
                    Text("No conversations yet")
                        .foregroundStyle(.secondary)
                    Spacer()
                } else if !appState.conversations.isEmpty {
                    List(appState.conversations) { item in
                        Button {
                            appState.openConversation(peerUserId: item.peerUserId)
                            showingChat = true
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(item.peerUserId)
                                        .font(.headline)
                                    if item.unreadCount > 0 {
                                        Text("\(item.unreadCount)")
                                            .font(.caption2)
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(Color.red.opacity(0.2))
                                            .clipShape(Capsule())
                                    }
                                }
                                Text(item.lastPreview)
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Conversations")
            .task {
                await appState.syncGroups()
            }
            .sheet(isPresented: $showingChat) {
                ChatView(peerUserId: appState.selectedPeer)
                    .environmentObject(appState)
            }
            .sheet(isPresented: $showingGroupChat) {
                if let group = selectedGroup {
                    GroupChatView(group: group)
                        .environmentObject(appState)
                }
            }
            .alert("Create Group", isPresented: $showingCreateGroup) {
                TextField("Group Name", text: $newGroupName)
                TextField("Members (comma-separated)", text: $newGroupMembers)
                    .textInputAutocapitalization(.never)
                Button("Create") {
                    let name = newGroupName
                    let members = newGroupMembers
                        .split(separator: ",")
                        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                        .filter { !$0.isEmpty }
                    newGroupName = ""
                    newGroupMembers = ""
                    Task { await appState.createGroup(name: name, memberIds: members) }
                }
                Button("Cancel", role: .cancel) {
                    newGroupName = ""
                    newGroupMembers = ""
                }
            }
        }
    }
}
