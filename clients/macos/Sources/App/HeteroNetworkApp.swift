import AppKit
import os
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()

    private let logger = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "HeteroNetwork",
        category: "Application"
    )

    func application(_ application: NSApplication, open urls: [URL]) {
        guard let importURL = urls.first(where: {
            $0.scheme == "heteronetwork" && $0.host == "import"
        }) else { return }
        handleImportURL(importURL)
        application.activate(ignoringOtherApps: true)
    }

    func handleImportURL(_ importURL: URL) {
        guard importURL.scheme == "heteronetwork", importURL.host == "import" else { return }
        logger.info("Received an import profile URL")
        model.importInput = importURL.absoluteString
    }
}

@main
struct HeteroNetworkApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        MenuBarExtra {
            MenuBarContent(model: appDelegate.model)
        } label: {
            MenuBarStatusLabel(model: appDelegate.model)
        }
        .menuBarExtraStyle(.window)

        Window("HeteroNetwork", id: "settings") {
            SettingsView(model: appDelegate.model)
                .onOpenURL { url in
                    appDelegate.handleImportURL(url)
                }
        }
        .handlesExternalEvents(matching: ["import"])
        .windowResizability(.contentSize)
    }
}

private struct MenuBarStatusLabel: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Image(systemName: model.vpnStatus.symbolName)
            .accessibilityLabel(model.vpnStatus.displayName)
    }
}
