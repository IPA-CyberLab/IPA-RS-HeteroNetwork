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
            Text(
                "The VPN profile and local identity will be deleted. "
                    + "Control-plane cleanup is best effort when the service is unavailable."
            )
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
            Section("SSH sponsor registration") {
                Button {
                    model.generateRegistrationRequest()
                } label: {
                    Label("Generate registration request", systemImage: "key.horizontal")
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isBusy)
                if !model.registrationRequest.isEmpty {
                    ScrollView {
                        Text(model.registrationRequest)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                    }
                    .frame(height: 88)
                    .background(Color.secondary.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                    Button {
                        model.copyRegistrationRequest()
                    } label: {
                        Label("Copy request", systemImage: "doc.on.doc")
                    }
                }
            }
            Section("Import profile") {
                TextEditor(text: $model.importInput)
                    .font(.system(.caption, design: .monospaced))
                    .frame(height: 72)
                    .overlay {
                        RoundedRectangle(cornerRadius: 4)
                            .stroke(Color.secondary.opacity(0.25))
                    }
                Button {
                    Task { await model.importProfile() }
                } label: {
                    Label("Import profile", systemImage: "square.and.arrow.down")
                }
                .buttonStyle(.borderedProminent)
                .disabled(
                    model.importInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                        || model.isBusy
                )
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
                    .disabled(model.isBusy || isTransitioning || model.vpnStatus != .connected)
                    Button {
                        model.openWebUI()
                    } label: {
                        Label("Open Web UI", systemImage: "rectangle.connected.to.line.below")
                    }
                    .disabled(model.vpnStatus != .connected)
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
