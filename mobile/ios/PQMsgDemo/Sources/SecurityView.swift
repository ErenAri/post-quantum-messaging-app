import SwiftUI

struct SecurityView: View {
    @EnvironmentObject private var appState: AppState
    @EnvironmentObject private var pushManager: PushManager

    var body: some View {
        NavigationStack {
            Form {
                Section("Crypto Profile") {
                    Text(appState.cryptoProfile)
                        .font(.caption)
                        .textSelection(.enabled)
                    Button("Refresh Security Snapshot") {
                        appState.refreshSecuritySnapshot()
                    }
                }

                Section("Transport") {
                    Text(transportLine())
                        .font(.caption)
                }

                Section("Push") {
                    Button("Request APNs Token") {
                        pushManager.requestAuthorizationAndRegister()
                    }
                    Text("APNs token: \(pushManager.apnsTokenHex.isEmpty ? "not registered" : pushManager.apnsTokenHex)")
                        .font(.caption)
                        .textSelection(.enabled)
                    if !pushManager.lastError.isEmpty {
                        Text(pushManager.lastError)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }

                Section("Pinned Identities") {
                    if appState.pinnedIdentities.isEmpty {
                        Text("No pinned identities for current user.")
                            .font(.caption)
                    } else {
                        ForEach(appState.pinnedIdentities, id: \.peerUserId) { record in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(record.peerUserId)
                                    .font(.headline)
                                Text(record.pin.fingerprintSha256)
                                    .font(.caption2)
                                    .textSelection(.enabled)
                                Text("Version \(record.pin.identityKeyVersion)")
                                    .font(.caption2)
                            }
                        }
                    }
                }

                Section("Local Security State") {
                    Text("Conversations: \(appState.conversations.count)")
                    Text("Sessions: \(LocalStateStore.shared.countSessions(userId: appState.setup.userId, peers: appState.conversations))")
                }
            }
            .navigationTitle("Security")
        }
    }

    private func transportLine() -> String {
        do {
            _ = try ApiClient(serverURL: appState.setup.serverURL)
            return "Transport policy accepted for \(appState.setup.serverURL)"
        } catch {
            return "Transport policy error: \(error.localizedDescription)"
        }
    }
}
