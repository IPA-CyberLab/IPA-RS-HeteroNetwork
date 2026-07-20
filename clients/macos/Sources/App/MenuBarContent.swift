import AppKit
import NetworkExtension
import SwiftUI

struct MenuBarContent: View {
    @ObservedObject var model: AppModel

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
            }
            Button {
                NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
                NSApp.activate(ignoringOtherApps: true)
            } label: {
                Label("Settings", systemImage: "gearshape")
            }
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
    private var connectionButton: some View {
        switch model.vpnStatus {
        case .connected, .connecting, .reasserting:
            Button {
                model.disconnect()
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
        @unknown default:
            EmptyView()
        }
    }
}
