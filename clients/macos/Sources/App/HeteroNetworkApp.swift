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
        guard let enrollmentURL = urls.first(where: { $0.scheme == "heteronetwork" }) else { return }
        handleEnrollmentURL(enrollmentURL)
        application.activate(ignoringOtherApps: true)
    }

    func handleEnrollmentURL(_ enrollmentURL: URL) {
        guard enrollmentURL.scheme == "heteronetwork" else { return }
        logger.info("Received an enrollment URL")
        model.enrollmentInput = enrollmentURL.absoluteString
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
                    appDelegate.handleEnrollmentURL(url)
                }
        }
        .handlesExternalEvents(matching: ["enroll"])
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
