import SwiftUI

struct GroupChatView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    let group: GroupSummary
    @State private var draftMessage = ""
    @State private var showingInfo = false
    @State private var showingAddMember = false
    @State private var newMemberId = ""
    @State private var members: [GroupMemberRecord] = []

    var body: some View {
        NavigationStack {
            VStack(spacing: 10) {
                HStack {
                    Text(group.displayName)
                        .font(.headline)
                    Spacer()
                    Button("Info") { showingInfo = true }
                        .buttonStyle(.bordered)
                    Button("Add") { showingAddMember = true }
                        .buttonStyle(.bordered)
                }
                .padding(.horizontal)
                .padding(.top, 8)

                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        if appState.groupChatLog.isEmpty {
                            Text("No messages yet")
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(Array(appState.groupChatLog.enumerated()), id: \.offset) { _, line in
                                Text(line)
                                    .font(.system(.footnote, design: .monospaced))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(8)
                .background(Color(white: 0.95))
                .cornerRadius(8)
                .padding(.horizontal)

                HStack {
                    TextField("Message", text: $draftMessage, axis: .vertical)
                        .textFieldStyle(.roundedBorder)
                        .lineLimit(1...4)
                    Button("Send") {
                        let text = draftMessage
                        draftMessage = ""
                        Task {
                            await appState.sendGroupMessage(groupId: group.groupId, text: text)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(draftMessage.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                .padding(.horizontal)
                .padding(.bottom, 12)

                if !appState.errorLine.isEmpty {
                    Text(appState.errorLine)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .padding(.horizontal)
                }
            }
            .navigationTitle("Group Chat")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Close") { dismiss() }
                }
            }
            .onAppear {
                appState.loadGroupChatLog(groupId: group.groupId)
            }
            .sheet(isPresented: $showingInfo) {
                NavigationStack {
                    List(members) { member in
                        VStack(alignment: .leading) {
                            Text(member.user_id).font(.headline)
                            Text("Role: \(member.role) | Joined: \(member.joined_at)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .navigationTitle("Members")
                    .toolbar {
                        ToolbarItem(placement: .topBarTrailing) {
                            Button("Done") { showingInfo = false }
                        }
                    }
                    .task {
                        members = await appState.listGroupMembers(groupId: group.groupId)
                    }
                }
            }
            .alert("Add Member", isPresented: $showingAddMember) {
                TextField("User ID", text: $newMemberId)
                    .textInputAutocapitalization(.never)
                Button("Add") {
                    let id = newMemberId
                    newMemberId = ""
                    Task { await appState.addGroupMember(groupId: group.groupId, memberId: id) }
                }
                Button("Cancel", role: .cancel) { newMemberId = "" }
            }
        }
    }
}
