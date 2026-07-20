import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func application(_ application: NSApplication, open urls: [URL]) {
        guard let enrollmentURL = urls.first(where: { $0.scheme == "heteronetwork" }) else { return }
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: .heteroNetworkEnrollmentURL, object: enrollmentURL)
            application.activate(ignoringOtherApps: true)
            application.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        }
    }
}

@main
struct HeteroNetworkApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuBarContent(model: model)
        } label: {
            Image(systemName: model.vpnStatus.symbolName)
                .accessibilityLabel("HeteroNetwork")
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(model: model)
        }
    }
}
