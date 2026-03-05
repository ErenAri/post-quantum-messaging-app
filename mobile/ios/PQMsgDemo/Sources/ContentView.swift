import SwiftUI

struct ContentView: View {
    var body: some View {
        TabView {
            SetupView()
                .tabItem {
                    Label("Setup", systemImage: "gearshape")
                }

            ConversationsView()
                .tabItem {
                    Label("Chats", systemImage: "message")
                }

            SecurityView()
                .tabItem {
                    Label("Security", systemImage: "lock.shield")
                }
        }
    }
}
