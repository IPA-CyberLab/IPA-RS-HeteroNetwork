import AppKit
import SwiftUI

struct MenuBarContent: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(model.vpnStatus.displayName, systemImage: model.vpnStatus.symbolName)
                .font(.headline)
            if let session = model.session {
                Text(session.client.vpnIP)
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.secondary)
                Divider()
                connectionButton
                if model.vpnStatus == .connected {
                    Button {
                        model.openWebUI()
                    } label: {
                        Label("Open Web UI", systemImage: "rectangle.connected.to.line.below")
                    }
                }
            }
            Button {
                openWindow(id: "settings")
                NSApp.activate(ignoringOtherApps: true)
            } label: {
                Label("Settings", systemImage: "gearshape")
            }
            Divider()
            updateControl
            Divider()
            Button {
                NSApp.terminate(nil)
            } label: {
                Label("Quit HeteroNetwork", systemImage: "power")
            }
        }
        .padding(12)
        .frame(width: 260)
    }

    @ViewBuilder
    private var updateControl: some View {
        switch model.updateStatus {
        case .checking:
            Label("Checking for updates…", systemImage: "arrow.triangle.2.circlepath")
        case .available(let tag):
            Button {
                Task { await model.installAvailableUpdate() }
            } label: {
                Label("Update to \(tag)", systemImage: "arrow.down.circle")
            }
        case .downloading(let tag):
            Label("Downloading \(tag)…", systemImage: "arrow.down.circle")
        case .restarting(let tag):
            Label("Restarting into \(tag)…", systemImage: "arrow.clockwise.circle")
        case .failed:
            Button {
                Task {
                    if model.canRetryAvailableUpdate {
                        await model.installAvailableUpdate()
                    } else {
                        await model.checkForUpdates()
                    }
                }
            } label: {
                Label("Retry Update", systemImage: "arrow.clockwise")
            }
        case .idle, .upToDate, .unavailableForDevelopmentBuild:
            Button {
                Task { await model.checkForUpdates() }
            } label: {
                Label("Check for Updates", systemImage: "arrow.clockwise")
            }
        }
    }

    @ViewBuilder
    private var connectionButton: some View {
        switch model.vpnStatus {
        case .connected, .connecting, .reasserting:
            Button {
                Task { await model.disconnect() }
            } label: {
                Label("Disconnect", systemImage: "stop.fill")
            }
            .disabled(model.isBusy)
        case .invalid, .disconnected, .disconnecting:
            Button {
                Task { await model.connect() }
            } label: {
                Label("Connect", systemImage: "play.fill")
            }
            .disabled(model.isBusy || model.vpnStatus == .disconnecting)
        }
    }
}
