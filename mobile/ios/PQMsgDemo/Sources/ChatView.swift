import SwiftUI

struct ChatView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var peer: String
    @State private var typingDebounceTask: Task<Void, Never>?
    @State private var pollingTask: Task<Void, Never>?
    @State private var showEphemeralPicker = false

    private let ephemeralOptions: [(String, Int)] = [
        ("Off", 0),
        ("30s", 30),
        ("5 min", 300),
        ("1 hr", 3600),
        ("24 hr", 86400),
    ]

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

                // Presence & typing indicator bar
                HStack(spacing: 8) {
                    Circle()
                        .fill(appState.peerPresenceOnline ? Color.green : Color.gray)
                        .frame(width: 10, height: 10)
                    Text(appState.peerPresenceOnline ? "Online" : "Offline")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if appState.peerIsTyping {
                        Text("typing...")
                            .font(.caption)
                            .foregroundStyle(.blue)
                    }
                    Spacer()
                    if appState.sealedSenderEnabled {
                        Image(systemName: "lock.shield")
                            .foregroundStyle(.purple)
                            .font(.caption)
                    }
                    if appState.ephemeralTtlSeconds > 0 {
                        Image(systemName: "timer")
                            .foregroundStyle(.orange)
                            .font(.caption)
                        Text("\(appState.ephemeralTtlSeconds)s")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
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

                    Button(appState.sealedSenderEnabled ? "Sealed: ON" : "Sealed: OFF") {
                        appState.toggleSealedSender()
                    }
                    .buttonStyle(.bordered)
                    .tint(appState.sealedSenderEnabled ? .purple : .gray)

                    Button("TTL") {
                        showEphemeralPicker = true
                    }
                    .buttonStyle(.bordered)
                    .tint(appState.ephemeralTtlSeconds > 0 ? .orange : .gray)
                }

                HStack {
                    TextField("Message", text: $appState.draftMessage, axis: .vertical)
                        .textFieldStyle(.roundedBorder)
                        .lineLimit(1...4)
                        .onChange(of: appState.draftMessage) { _, _ in
                            onDraftChanged()
                        }
                    Button("Send") {
                        appState.openConversation(peerUserId: peer)
                        Task { await sendMessage() }
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
                        stopPolling()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    HStack(spacing: 12) {
                        Button {
                            Task { await appState.startOutgoingCall(peerUserId: peer, callType: "audio") }
                        } label: {
                            Image(systemName: "phone.fill")
                        }
                        Button {
                            Task { await appState.startOutgoingCall(peerUserId: peer, callType: "video") }
                        } label: {
                            Image(systemName: "video.fill")
                        }
                    }
                }
            }
            .sheet(isPresented: $appState.showCallView) {
                CallView()
                    .environmentObject(appState)
            }
            .onAppear {
                appState.openConversation(peerUserId: peer)
                startPolling()
                Task {
                    await appState.sendPresenceHeartbeat()
                }
            }
            .onDisappear {
                stopPolling()
            }
            .confirmationDialog("Ephemeral Timer", isPresented: $showEphemeralPicker) {
                ForEach(ephemeralOptions, id: \.1) { label, seconds in
                    Button(label) {
                        appState.setEphemeralTtl(seconds)
                    }
                }
                Button("Cancel", role: .cancel) {}
            }
        }
    }

    private func sendMessage() async {
        if appState.ephemeralTtlSeconds > 0 {
            await appState.sendEphemeralMessage(peerUserId: peer)
        } else if appState.sealedSenderEnabled {
            await appState.sendSealedMessage(peerUserId: peer)
        } else {
            await appState.sendMessage(peerUserId: peer)
        }
    }

    private func onDraftChanged() {
        typingDebounceTask?.cancel()
        typingDebounceTask = Task {
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard !Task.isCancelled else { return }
            await appState.notifyTyping(peerUserId: peer, isTyping: true)
        }
    }

    private func startPolling() {
        pollingTask = Task {
            while !Task.isCancelled {
                async let _ = appState.pollPresence(peerUserId: peer)
                async let _ = appState.pollTyping()
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    private func stopPolling() {
        pollingTask?.cancel()
        pollingTask = nil
        typingDebounceTask?.cancel()
        typingDebounceTask = nil
    }
}
