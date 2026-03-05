import SwiftUI

@main
struct PQMsgDemoApp: App {
    @UIApplicationDelegateAdaptor(PushManager.self) private var pushManager
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .environmentObject(pushManager)
        }
    }
}
