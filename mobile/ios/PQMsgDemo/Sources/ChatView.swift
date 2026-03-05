import SwiftUI

struct ChatView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var peer: String

    init(peerUserId: String) {
        _peer = State(initialValue: peerUserId)
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 10) {
                Group {
                    TextField(
                        "Server URL",
                        text: Binding(
                            get: { appState.setup.serverURL },
                            set: { appState.setServerURL($0) }
                        )
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)

                    TextField(
                        "User ID",
                        text: Binding(
                            get: { appState.setup.userId },
                            set: { appState.setUserId($0) }
                        )
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)

                    TextField("Peer User ID", text: $peer)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textFieldStyle(.roundedBorder)
                }
                .padding(.horizontal)

                HStack {
                    Button("Fetch Bundle") {
                        appState.openConversation(peerUserId: peer)
                        Task { await appState.fetchBundle(peerUserId: peer) }
                    }
                    .buttonStyle(.bordered)

                    Button("Poll Inbox") {
                        Task { await appState.pollInbox() }
                    }
                    .buttonStyle(.bordered)
                }

                HStack {
                    TextField("Message", text: $appState.draftMessage, axis: .vertical)
                        .textFieldStyle(.roundedBorder)
                        .lineLimit(1...4)
                    Button("Send") {
                        appState.openConversation(peerUserId: peer)
                        Task { await appState.sendMessage(peerUserId: peer) }
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding(.horizontal)

                VStack(alignment: .leading, spacing: 6) {
                    Text("Status: \(appState.statusLine)")
                        .font(.caption)
                    if !appState.errorLine.isEmpty {
                        Text(appState.errorLine)
                            .font(.caption)
                            .foregroundStyle(.red)
                            .textSelection(.enabled)
                    }
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 4) {
                            ForEach(Array(appState.chatLog.enumerated()), id: \.offset) { _, line in
                                Text(line)
                                    .font(.system(.footnote, design: .monospaced))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(8)
                    .background(Color(white: 0.95))
                    .cornerRadius(8)
                }
                .padding(.horizontal)
                .padding(.bottom, 12)
            }
            .navigationTitle("Chat")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Close") {
                        dismiss()
                    }
                }
            }
            .onAppear {
                appState.openConversation(peerUserId: peer)
            }
        }
    }
}
