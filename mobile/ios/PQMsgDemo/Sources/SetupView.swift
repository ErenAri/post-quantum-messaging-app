import SwiftUI
import UIKit

struct SetupView: View {
    @EnvironmentObject private var appState: AppState
    @EnvironmentObject private var pushManager: PushManager
    @State private var onboardingPassphrase = ""
    @State private var onboardingPackageText = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Identity Presets") {
                    HStack {
                        Button("Preset Alice") {
                            appState.applyPreset(userId: "alice", peerId: "bob")
                        }
                        Button("Preset Bob") {
                            appState.applyPreset(userId: "bob", peerId: "alice")
                        }
                    }
                }

                Section("Endpoint and Identity") {
                    TextField(
                        "Server URL",
                        text: Binding(
                            get: { appState.setup.serverURL },
                            set: { appState.setServerURL($0) }
                        )
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                    TextField(
                        "User ID",
                        text: Binding(
                            get: { appState.setup.userId },
                            set: { appState.setUserId($0) }
                        )
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                    TextField(
                        "Device ID",
                        text: Binding(
                            get: { appState.setup.deviceId },
                            set: { appState.setDeviceId($0) }
                        )
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                    TextField(
                        "Suite (ml-kem-768 or kyber768)",
                        text: Binding(
                            get: { appState.setup.suiteLabel },
                            set: { appState.setSuiteLabel($0) }
                        )
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                    TextField(
                        "Peer User ID",
                        text: Binding(
                            get: { appState.setup.peerUserId },
                            set: { appState.setPeerUserId($0) }
                        )
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                }

                Section("Provisioning State") {
                    Text("1) Generate keys: \(flag(appState.progress.keysGenerated))")
                    Text("2) Register user: \(flag(appState.progress.userRegistered))")
                    Text("3) Publish prekeys: \(flag(appState.progress.prekeysPublished))")
                    Text("4) Verify server: \(flag(appState.progress.serverVerified))")
                    if appState.progress.isAdoptedLinkedDevice() {
                        Text("Linked device imported. Verify server to finish local trust bootstrap.")
                            .font(.caption)
                    }
                }

                Section("Import Linked Device") {
                    SecureField("Package Passphrase", text: $onboardingPassphrase)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextEditor(text: $onboardingPackageText)
                        .font(.caption.monospaced())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .frame(minHeight: 200)
                    HStack {
                        Button("Paste Package") {
                            onboardingPackageText = UIPasteboard.general.string ?? ""
                        }
                        Button("Import Package") {
                            Task {
                                await appState.importLinkedDeviceOnboarding(
                                    packageText: onboardingPackageText,
                                    passphrase: onboardingPassphrase
                                )
                                if appState.errorLine.isEmpty && appState.progress.isAdoptedLinkedDevice() {
                                    onboardingPassphrase = ""
                                    onboardingPackageText = ""
                                }
                            }
                        }
                        .disabled(
                            onboardingPackageText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                            onboardingPassphrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                        )
                    }
                    Text("Use the sealed package text from the primary device, then publish this device's prekeys automatically.")
                        .font(.caption)
                }

                Section("Actions") {
                    Button("Generate Identity Keys") {
                        Task { await appState.generateKeys() }
                    }
                    Button("Register User") {
                        Task { await appState.registerUser() }
                    }
                    .disabled(!appState.progress.canRegister())

                    Button("Publish Prekeys") {
                        Task { await appState.publishPrekeys() }
                    }
                    .disabled(!appState.progress.canPublishPrekeys())

                    Button("Verify Server") {
                        Task { await appState.verifyServer(pushToken: pushManager.apnsTokenHex) }
                    }
                    .disabled(!appState.progress.canVerifyServer())

                    Button("Request APNs Token") {
                        pushManager.requestAuthorizationAndRegister()
                    }

                    Text("APNs token: \(pushManager.apnsTokenHex.isEmpty ? "not registered" : pushManager.apnsTokenHex)")
                        .font(.caption)
                        .textSelection(.enabled)
                }

                Section("Runtime") {
                    Text("Crypto profile")
                        .font(.headline)
                    Text(appState.cryptoProfile)
                        .font(.caption)
                        .textSelection(.enabled)
                    Text("Status: \(appState.statusLine)")
                    if !appState.errorLine.isEmpty {
                        Text(appState.errorLine)
                            .foregroundStyle(.red)
                            .font(.caption)
                            .textSelection(.enabled)
                    }
                    if !pushManager.lastError.isEmpty {
                        Text("Push error: \(pushManager.lastError)")
                            .foregroundStyle(.red)
                            .font(.caption)
                    }
                    Text(appState.progress.canOpenConversations() ? "Conversations tab is ready." : "Complete setup steps before chat.")
                        .font(.caption)
                }
            }
            .navigationTitle("Setup")
        }
    }

    private func flag(_ value: Bool) -> String {
        value ? "done" : "pending"
    }
}
