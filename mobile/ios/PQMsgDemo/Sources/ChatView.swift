import PhotosUI
import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct ChatView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var peer: String
    @State private var typingDebounceTask: Task<Void, Never>?
    @State private var pollingTask: Task<Void, Never>?
    @State private var showEphemeralPicker = false
    @State private var showAttachmentSheet = false
    @State private var showMediaPicker = false
    @State private var showAudioImporter = false
    @State private var showDocumentImporter = false
    @State private var showCameraCapture = false
    @State private var selectedMediaItem: PhotosPickerItem?

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

    private var canSend: Bool {
        !appState.draftMessage.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || appState.pendingAttachment != nil
    }

    @ViewBuilder
    private var attachmentSheet: some View {
        ZStack(alignment: .bottom) {
            Color.black.opacity(0.24)
                .ignoresSafeArea()
                .onTapGesture {
                    showAttachmentSheet = false
                }

            VStack(alignment: .leading, spacing: 18) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Share something")
                        .font(.headline)
                    Text("Choose what to send in this chat.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                    AttachmentActionButton(
                        title: "Camera",
                        subtitle: "Capture a photo",
                        systemImage: "camera.fill",
                        tint: .green
                    ) {
                        openAttachmentFlow {
                            guard UIImagePickerController.isSourceTypeAvailable(.camera) else {
                                presentAttachmentError("Open camera", message: "Camera is not available on this device.")
                                return
                            }
                            showCameraCapture = true
                        }
                    }
                    AttachmentActionButton(
                        title: "Photos & Videos",
                        subtitle: "Pick from your library",
                        systemImage: "photo.on.rectangle.angled",
                        tint: .blue
                    ) {
                        openAttachmentFlow {
                            showMediaPicker = true
                        }
                    }
                    AttachmentActionButton(
                        title: "Audio",
                        subtitle: "Share a sound file",
                        systemImage: "waveform",
                        tint: .orange
                    ) {
                        openAttachmentFlow {
                            showAudioImporter = true
                        }
                    }
                    AttachmentActionButton(
                        title: "Document",
                        subtitle: "Browse files and folders",
                        systemImage: "doc.fill",
                        tint: .purple
                    ) {
                        openAttachmentFlow {
                            showDocumentImporter = true
                        }
                    }
                }

                Button("Cancel", role: .cancel) {
                    showAttachmentSheet = false
                }
                .buttonStyle(.bordered)
                .frame(maxWidth: .infinity, alignment: .center)
            }
            .padding(20)
            .frame(maxWidth: .infinity)
            .background(.ultraThinMaterial)
            .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
            .padding(.horizontal, 14)
            .padding(.bottom, 12)
        }
        .transition(.opacity)
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

                VStack(spacing: 10) {
                    HStack(alignment: .bottom, spacing: 12) {
                        Button {
                            showAttachmentSheet = true
                        } label: {
                            Image(systemName: "paperclip.circle.fill")
                                .font(.system(size: 28))
                                .foregroundStyle(.blue)
                        }
                        .accessibilityLabel("Open attachment options")

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
                        .disabled(!canSend)
                    }

                    if let attachment = appState.pendingAttachment {
                        HStack(spacing: 10) {
                            Image(systemName: attachmentIconName(for: attachment.mimeType))
                                .foregroundStyle(.blue)
                                .font(.headline)
                                .frame(width: 28)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(attachment.fileName)
                                    .font(.subheadline.weight(.semibold))
                                    .lineLimit(1)
                                Text("\(attachment.mimeType) - \(attachment.byteLength) bytes")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                            Spacer()
                            Button {
                                appState.clearPendingAttachment()
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundStyle(.secondary)
                                    .font(.title3)
                            }
                            .accessibilityLabel("Clear attachment")
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(Color.blue.opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                    }
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
            .photosPicker(
                isPresented: $showMediaPicker,
                selection: $selectedMediaItem,
                matching: .any(of: [.images, .videos])
            )
            .fileImporter(
                isPresented: $showAudioImporter,
                allowedContentTypes: [.audio]
            ) { result in
                handleImportedFile(result, action: "Select audio")
            }
            .fileImporter(
                isPresented: $showDocumentImporter,
                allowedContentTypes: [.item]
            ) { result in
                handleImportedFile(result, action: "Select document")
            }
            .fullScreenCover(isPresented: $showCameraCapture) {
                CameraCaptureView(
                    onCapture: { image in
                        handleCapturedImage(image)
                        showCameraCapture = false
                    },
                    onCancel: {
                        showCameraCapture = false
                    }
                )
                .ignoresSafeArea()
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
            .overlay {
                if showAttachmentSheet {
                    attachmentSheet
                }
            }
            .onChange(of: selectedMediaItem) { _, item in
                guard let item else { return }
                Task {
                    await handleSelectedMedia(item)
                }
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

    private func openAttachmentFlow(_ action: @escaping () -> Void) {
        showAttachmentSheet = false
        DispatchQueue.main.async {
            action()
        }
    }

    private func handleImportedFile(_ result: Result<URL, Error>, action: String) {
        switch result {
        case .success(let url):
            Task {
                await stageImportedFile(url, action: action)
            }
        case .failure(let error):
            presentAttachmentError(action, message: error.localizedDescription)
        }
    }

    private func stageImportedFile(_ url: URL, action: String) async {
        let didStartAccess = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccess {
                url.stopAccessingSecurityScopedResource()
            }
        }
        do {
            let data = try Data(contentsOf: url)
            let fileName = url.lastPathComponent.isEmpty ? "attachment.bin" : url.lastPathComponent
            let mimeType = UTType(filenameExtension: url.pathExtension)?.preferredMIMEType ?? "application/octet-stream"
            try appState.stageAttachment(fileName: fileName, mimeType: mimeType, data: data)
        } catch {
            presentAttachmentError(action, message: error.localizedDescription)
        }
    }

    private func handleCapturedImage(_ image: UIImage) {
        guard let data = image.jpegData(compressionQuality: 0.72) else {
            presentAttachmentError("Capture photo", message: "Unable to encode captured photo.")
            return
        }
        do {
            try appState.stageAttachment(
                fileName: "camera-\(Int(Date().timeIntervalSince1970)).jpg",
                mimeType: "image/jpeg",
                data: data
            )
        } catch {
            presentAttachmentError("Capture photo", message: error.localizedDescription)
        }
    }

    private func handleSelectedMedia(_ item: PhotosPickerItem) async {
        defer {
            selectedMediaItem = nil
        }
        do {
            guard let data = try await item.loadTransferable(type: Data.self) else {
                presentAttachmentError("Select media", message: "Unable to read the selected media.")
                return
            }
            let contentType = item.supportedContentTypes.first ?? .data
            let fileName = suggestedFileName(for: contentType)
            let mimeType = contentType.preferredMIMEType ?? "application/octet-stream"
            try appState.stageAttachment(fileName: fileName, mimeType: mimeType, data: data)
        } catch {
            presentAttachmentError("Select media", message: error.localizedDescription)
        }
    }

    private func suggestedFileName(for contentType: UTType) -> String {
        let timestamp = Int(Date().timeIntervalSince1970)
        let ext = contentType.preferredFilenameExtension ?? "bin"
        let baseName = contentType.conforms(to: .movie) ? "video" : "photo"
        return "\(baseName)-\(timestamp).\(ext)"
    }

    private func attachmentIconName(for mimeType: String) -> String {
        if mimeType.hasPrefix("image/") {
            return "photo"
        }
        if mimeType.hasPrefix("video/") {
            return "video"
        }
        if mimeType.hasPrefix("audio/") {
            return "waveform"
        }
        return "doc"
    }

    private func presentAttachmentError(_ action: String, message: String) {
        appState.errorLine = "\(action) failed: \(message)"
        appState.statusLine = "\(action) failed"
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

private struct AttachmentActionButton: View {
    let title: String
    let subtitle: String
    let systemImage: String
    let tint: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 12) {
                Image(systemName: systemImage)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(tint)
                    .frame(width: 44, height: 44)
                    .background(tint.opacity(0.14))
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.leading)
            }
            .frame(maxWidth: .infinity, minHeight: 128, alignment: .topLeading)
            .padding(14)
            .background(Color.primary.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        }
        .buttonStyle(.plain)
    }
}

private struct CameraCaptureView: UIViewControllerRepresentable {
    let onCapture: (UIImage) -> Void
    let onCancel: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onCapture: onCapture, onCancel: onCancel)
    }

    func makeUIViewController(context: Context) -> UIImagePickerController {
        let picker = UIImagePickerController()
        picker.sourceType = .camera
        picker.allowsEditing = false
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ uiViewController: UIImagePickerController, context: Context) {}

    final class Coordinator: NSObject, UINavigationControllerDelegate, UIImagePickerControllerDelegate {
        private let onCapture: (UIImage) -> Void
        private let onCancel: () -> Void

        init(onCapture: @escaping (UIImage) -> Void, onCancel: @escaping () -> Void) {
            self.onCapture = onCapture
            self.onCancel = onCancel
        }

        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
            onCancel()
        }

        func imagePickerController(
            _ picker: UIImagePickerController,
            didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]
        ) {
            if let image = info[.originalImage] as? UIImage {
                onCapture(image)
            } else {
                onCancel()
            }
        }
    }
}
