import SwiftUI

struct CallView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    var body: some View {
        ZStack {
            LinearGradient(
                gradient: Gradient(colors: [Color(red: 0.05, green: 0.05, blue: 0.15), .black]),
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            VStack(spacing: 24) {
                Spacer()

                // Avatar
                Circle()
                    .fill(Color.green.opacity(0.2))
                    .frame(width: 120, height: 120)
                    .overlay(
                        Text(peerInitial)
                            .font(.system(size: 48, weight: .bold))
                            .foregroundColor(.green)
                    )
                    .overlay(
                        Circle().stroke(Color.green.opacity(0.4), lineWidth: 3)
                    )

                // Peer name
                Text(appState.activeCallPeer ?? "Unknown")
                    .font(.title)
                    .foregroundColor(.white)
                    .fontWeight(.semibold)

                // Call status
                Text(appState.callStatus)
                    .font(.body)
                    .foregroundColor(.white.opacity(0.7))

                // Timer
                if appState.callStatus == "Connected" {
                    Text(formattedTime)
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(.white.opacity(0.6))

                    // PQ badge
                    HStack(spacing: 4) {
                        Image(systemName: "shield.checkered")
                            .font(.caption)
                        Text("PQ-Protected")
                            .font(.caption2)
                    }
                    .foregroundColor(.green)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 4)
                    .background(Color.green.opacity(0.15))
                    .cornerRadius(12)
                }

                Spacer()

                // Incoming call actions
                if appState.isIncomingCall && appState.callStatus == "Ringing..." {
                    HStack(spacing: 40) {
                        Button {
                            Task { await appState.declineIncomingCall() }
                        } label: {
                            VStack(spacing: 6) {
                                Image(systemName: "phone.down.fill")
                                    .font(.title2)
                                    .frame(width: 56, height: 56)
                                    .background(Color.red)
                                    .foregroundColor(.white)
                                    .clipShape(Circle())
                                Text("Decline").font(.caption).foregroundColor(.white.opacity(0.7))
                            }
                        }

                        Button {
                            Task { await appState.acceptIncomingCall() }
                        } label: {
                            VStack(spacing: 6) {
                                Image(systemName: "phone.fill")
                                    .font(.title2)
                                    .frame(width: 56, height: 56)
                                    .background(Color.green)
                                    .foregroundColor(.white)
                                    .clipShape(Circle())
                                Text("Accept").font(.caption).foregroundColor(.white.opacity(0.7))
                            }
                        }
                    }
                    .padding(.bottom, 40)
                } else {
                    // Active call controls
                    HStack(spacing: 32) {
                        // Mute (placeholder)
                        Button {
                            // Mute toggle would go here with actual WebRTC
                        } label: {
                            Image(systemName: "mic.slash.fill")
                                .font(.title2)
                                .frame(width: 56, height: 56)
                                .background(Color.white.opacity(0.15))
                                .foregroundColor(.white)
                                .clipShape(Circle())
                        }

                        // Hangup
                        Button {
                            Task { await appState.hangupCall() }
                        } label: {
                            Image(systemName: "phone.down.fill")
                                .font(.title2)
                                .frame(width: 56, height: 56)
                                .background(Color.red)
                                .foregroundColor(.white)
                                .clipShape(Circle())
                        }

                        // Camera (placeholder)
                        if appState.activeCallType == "video" {
                            Button {
                                // Camera toggle would go here
                            } label: {
                                Image(systemName: "video.slash.fill")
                                    .font(.title2)
                                    .frame(width: 56, height: 56)
                                    .background(Color.white.opacity(0.15))
                                    .foregroundColor(.white)
                                    .clipShape(Circle())
                            }
                        }
                    }
                    .padding(.bottom, 40)
                }
            }
            .padding()
        }
    }

    private var peerInitial: String {
        guard let first = appState.activeCallPeer?.first else { return "?" }
        return String(first).uppercased()
    }

    private var formattedTime: String {
        let mins = appState.callElapsedSeconds / 60
        let secs = appState.callElapsedSeconds % 60
        return String(format: "%02d:%02d", mins, secs)
    }
}
