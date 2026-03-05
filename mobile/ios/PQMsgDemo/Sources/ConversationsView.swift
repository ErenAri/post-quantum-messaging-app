import SwiftUI

struct ConversationsView: View {
    @EnvironmentObject private var appState: AppState
    @State private var showingChat = false

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
                        appState.refreshConversations()
                    }
                    .buttonStyle(.bordered)
                    Spacer()
                    Text(appState.statusLine)
                        .font(.caption)
                }
                .padding(.horizontal)

                if appState.conversations.isEmpty {
                    Spacer()
                    Text("No conversations yet")
                        .foregroundStyle(.secondary)
                    Spacer()
                } else {
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
            .sheet(isPresented: $showingChat) {
                ChatView(peerUserId: appState.selectedPeer)
                    .environmentObject(appState)
            }
        }
    }
}
