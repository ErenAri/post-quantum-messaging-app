import SwiftUI
import UIKit

struct SecurityView: View {
    @EnvironmentObject private var appState: AppState
    @EnvironmentObject private var pushManager: PushManager
    @State private var confirmingReset = false
    @State private var onboardingPassphrase = ""

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
                    Text("Server capabilities: \(appState.serverCapabilitiesSummary)")
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

                Section("Secondary Device Onboarding") {
                    TextField("Managed Device ID", text: $appState.managedDeviceId)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Package Passphrase", text: $onboardingPassphrase)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("Prepare Package") {
                        Task {
                            await appState.prepareSecondaryDeviceOnboarding(passphrase: onboardingPassphrase)
                            if appState.errorLine.isEmpty {
                                onboardingPassphrase = ""
                            }
                        }
                    }
                    .disabled(
                        appState.managedDeviceId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                        onboardingPassphrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    )
                    if let prepared = appState.preparedOnboardingPackage {
                        HStack {
                            Button("Copy Package") {
                                UIPasteboard.general.string = prepared.packageText
                                appState.statusLine = "Copied onboarding package for \(prepared.deviceId)"
                            }
                            Spacer()
                            Text(prepared.deviceId)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text("Prepared for \(prepared.userId) at \(prepared.linkedAt)")
                            .font(.caption)
                        TextEditor(text: .constant(prepared.packageText))
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .frame(minHeight: 200)
                    } else {
                        Text("Link a target device id and seal a portable onboarding package for the secondary device.")
                            .font(.caption)
                    }
                }

                Section("Devices") {
                    Text(appState.managedDeviceId.isEmpty ? "Set a managed device id above." : "Managed device target: \(appState.managedDeviceId)")
                        .font(.caption)
                    HStack {
                        Button("List Devices") {
                            Task { await appState.listDevices() }
                        }
                        Button("Link Device") {
                            Task { await appState.linkManagedDevice() }
                        }
                    }
                    Button("Revoke Device", role: .destructive) {
                        Task { await appState.revokeManagedDevice() }
                    }
                    if appState.linkedDevices.isEmpty {
                        Text("No linked-device snapshot loaded.")
                            .font(.caption)
                    } else {
                        ForEach(appState.linkedDevices) { device in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(device.device_id)
                                    .font(.headline)
                                Text(device.active ? "active" : "revoked at \(device.revoked_at ?? "unknown")")
                                    .font(.caption2)
                                Text("linked \(device.linked_at)")
                                    .font(.caption2)
                            }
                        }
                    }
                }

                Section("Local Security State") {
                    Text("Conversations: \(appState.conversations.count)")
                    Text("Sessions: \(LocalStateStore.shared.countSessions(userId: appState.setup.userId, peers: appState.conversations))")
                }

                Section("Reset") {
                    Button("Reset Local State", role: .destructive) {
                        confirmingReset = true
                    }
                    .disabled(appState.setup.userId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    Text("Retires the current device on the server when keys are still present, then deletes local keys, sessions, pins, cursors, and conversation metadata.")
                        .font(.caption)
                }
            }
            .navigationTitle("Security")
            .confirmationDialog(
                "Reset local state?",
                isPresented: $confirmingReset,
                titleVisibility: .visible
            ) {
                Button("Reset Local State", role: .destructive) {
                    Task {
                        if await appState.resetLocalState() {
                            pushManager.clearStoredToken()
                        }
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This retires the current device on the server when possible, then removes local identity material and metadata for \(appState.setup.userId).")
            }
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
