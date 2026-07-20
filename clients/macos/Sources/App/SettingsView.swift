import HeteroNetworkCore
import NetworkExtension
import SwiftUI

struct SettingsView: View {
    @ObservedObject var model: AppModel
    @State private var confirmRemoval = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if let session = model.session {
                configuredContent(session)
            } else {
                enrollmentContent
            }
        }
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
        .alert("Remove this Mac?", isPresented: $confirmRemoval) {
            Button("Cancel", role: .cancel) {}
            Button("Remove", role: .destructive) {
                Task { await model.removeThisMac() }
            }
        } message: {
            Text("The VPN profile and local identity will be deleted.")
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: model.vpnStatus.symbolName)
                .font(.system(size: 28))
                .foregroundStyle(statusColor)
                .frame(width: 36, height: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text("HeteroNetwork")
                    .font(.title2.weight(.semibold))
                Text(model.vpnStatus.displayName)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if model.isBusy {
                ProgressView()
                    .controlSize(.small)
            }
        }
        .padding(20)
    }

    private var enrollmentContent: some View {
        Form {
            Section("Enrollment") {
                SecureField("Enrollment link", text: $model.enrollmentInput)
                    .textFieldStyle(.roundedBorder)
                Button {
                    Task { await model.enroll() }
                } label: {
                    Label("Enroll this Mac", systemImage: "link.badge.plus")
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.enrollmentInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.isBusy)
            }
            errorSection
        }
        .formStyle(.grouped)
        .padding(.bottom, 8)
    }

    private func configuredContent(_ session: ClientSession) -> some View {
        Form {
            Section("Connection") {
                LabeledContent("VPN address", value: session.client.vpnIP)
                LabeledContent("Gateway", value: model.gatewayName)
                LabeledContent("Cluster", value: session.client.clusterID)
                LabeledContent("Last refresh", value: session.refreshedAt.formatted(date: .abbreviated, time: .shortened))
                HStack {
                    connectionButton
                    Button {
                        Task { await model.refresh() }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .disabled(model.isBusy || isTransitioning)
                }
            }
            Section("Identity") {
                LabeledContent("Client ID", value: session.client.nodeID)
                    .textSelection(.enabled)
                Button(role: .destructive) {
                    confirmRemoval = true
                } label: {
                    Label("Remove this Mac", systemImage: "trash")
                }
                .disabled(model.isBusy || isTransitioning)
            }
            errorSection
        }
        .formStyle(.grouped)
        .padding(.bottom, 8)
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
            .buttonStyle(.borderedProminent)
            .tint(.red)
            .disabled(model.isBusy)
        case .invalid, .disconnected, .disconnecting:
            Button {
                Task { await model.connect() }
            } label: {
                Label("Connect", systemImage: "play.fill")
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.isBusy || model.vpnStatus == .disconnecting)
        @unknown default:
            EmptyView()
        }
    }

    @ViewBuilder
    private var errorSection: some View {
        if let error = model.lastError {
            Section {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                    Text(error)
                        .textSelection(.enabled)
                    Spacer()
                    Button {
                        model.clearError()
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .buttonStyle(.plain)
                    .help("Dismiss")
                }
            }
        }
    }

    private var isTransitioning: Bool {
        [.connecting, .disconnecting, .reasserting].contains(model.vpnStatus)
    }

    private var statusColor: Color {
        switch model.vpnStatus {
        case .connected: return .green
        case .connecting, .disconnecting, .reasserting: return .orange
        case .invalid, .disconnected: return .secondary
        @unknown default: return .secondary
        }
    }
}
