import Foundation
import UIKit
import UserNotifications

final class PushManager: NSObject, UIApplicationDelegate, ObservableObject, UNUserNotificationCenterDelegate {
    @Published var apnsTokenHex: String
    @Published var lastError: String

    override init() {
        self.apnsTokenHex = UserDefaults.standard.string(forKey: "apns_token_hex") ?? ""
        self.lastError = ""
        super.init()
    }

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func requestAuthorizationAndRegister() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) { granted, error in
            DispatchQueue.main.async {
                if let error {
                    self.lastError = error.localizedDescription
                    return
                }
                if !granted {
                    self.lastError = "notification permission denied"
                    return
                }
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        apnsTokenHex = token
        UserDefaults.standard.set(token, forKey: "apns_token_hex")
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        lastError = error.localizedDescription
    }
}
