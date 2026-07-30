using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Windows.Media;
using System.Windows.Threading;
using HeteroNetwork.Core;
using Brush = System.Windows.Media.Brush;
using Brushes = System.Windows.Media.Brushes;

namespace HeteroNetwork.App;

public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private const int GatewayFailureThreshold = 2;
    private static readonly TimeSpan GatewayFailureCooldown = TimeSpan.FromSeconds(60);
    private readonly ClientSessionStore sessionStore = new();
    private readonly PendingClientRegistrationStore pendingStore = new();
    private readonly ControlPlaneClient controlPlane = new();
    private readonly WindowsTunnelManager tunnelManager;
    private readonly DispatcherTimer statusTimer;
    private readonly SemaphoreSlim backgroundGate = new(1, 1);
    private readonly Dictionary<string, DateTimeOffset> failedGateways = [];
    private ClientSession? session;
    private PendingClientRegistration? pendingRegistration;
    private TunnelConnectionStatus status;
    private bool isBusy;
    private string registrationRequest = string.Empty;
    private string importInput = string.Empty;
    private string? lastError;
    private int consecutiveProbeFailures;
    private DateTimeOffset profileActivatedAt = DateTimeOffset.MinValue;
    private bool disposed;

    public MainViewModel()
    {
        tunnelManager = new WindowsTunnelManager(sessionStore);
        status = tunnelManager.GetStatus();
        statusTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(5),
        };
        statusTimer.Tick += StatusTimer_Tick;
        statusTimer.Start();
        _ = RestoreAsync();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler<string>? ActivationAccepted;

    public bool IsConfigured => session is not null;
    public bool IsNotConfigured => !IsConfigured;
    public bool IsBusy => isBusy;
    public bool HasError => !string.IsNullOrWhiteSpace(lastError);
    public string? LastError => lastError;
    public bool WireGuardMissing => !tunnelManager.IsWireGuardInstalled;
    public bool IsConnected => status == TunnelConnectionStatus.Connected;
    public bool HasPendingRegistration => pendingRegistration is not null;
    public bool CanGenerateRegistration => !isBusy && session is null;
    public bool CanImport => !isBusy
        && session is null
        && pendingRegistration is not null
        && !string.IsNullOrWhiteSpace(importInput);
    public bool CanRefresh => !isBusy && IsConnected && session is not null;
    public string RegistrationRequest => registrationRequest;
    public string ImportInput
    {
        get => importInput;
        set
        {
            if (importInput == value)
            {
                return;
            }

            importInput = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanImport));
        }
    }

    public string VpnAddress => session?.Client.VpnIp ?? "-";
    public string GatewayName =>
        session?.SelectedGatewayNodeId ?? session?.PeerMap.Peers.FirstOrDefault()?.NodeId ?? "-";
    public string ClusterName => session?.Client.ClusterId ?? "-";
    public string ClientId => session?.Client.NodeId ?? "-";
    public string LastRefresh => session?.RefreshedAt.ToLocalTime().ToString("g") ?? "-";
    public string ConnectionAction => IsConnected || IsTransitioning ? "Disconnect" : "Connect";

    public string StatusDisplay => status switch
    {
        TunnelConnectionStatus.NotConfigured => "Not configured",
        TunnelConnectionStatus.Disconnected => "Disconnected",
        TunnelConnectionStatus.Connecting => "Connecting",
        TunnelConnectionStatus.Connected => "Connected",
        TunnelConnectionStatus.Disconnecting => "Disconnecting",
        TunnelConnectionStatus.Reconnecting => "Reconnecting",
        _ => "Unknown",
    };

    public Brush StatusBrush => status switch
    {
        TunnelConnectionStatus.Connected => Brushes.LimeGreen,
        TunnelConnectionStatus.Connecting
            or TunnelConnectionStatus.Disconnecting
            or TunnelConnectionStatus.Reconnecting => Brushes.Orange,
        _ => Brushes.LightSlateGray,
    };

    private bool IsTransitioning => status is TunnelConnectionStatus.Connecting
        or TunnelConnectionStatus.Disconnecting
        or TunnelConnectionStatus.Reconnecting;

    public void AcceptActivation(string value)
    {
        if (!ClientRegistrationProtocol.IsImportUri(value))
        {
            SetError("Only a HeteroNetwork import profile can be opened here.");
            return;
        }

        ImportInput = value;
        ActivationAccepted?.Invoke(this, value);
    }

    public string? GenerateRegistrationRequest()
    {
        if (isBusy || session is not null)
        {
            return null;
        }

        SetError(null);
        try
        {
            var generated = ClientRegistrationProtocol.GenerateRequest();
            pendingStore.Save(generated);
            pendingRegistration = generated;
            registrationRequest =
                ClientRegistrationProtocol.RegistrationUri(generated.Bundle);
            ImportInput = string.Empty;
            RaiseState();
            return registrationRequest;
        }
        catch (Exception error)
        {
            SetError(error.Message);
            RaiseState();
            return null;
        }
    }

    public async Task ImportAsync()
    {
        if (isBusy
            || session is not null
            || pendingRegistration is null
            || string.IsNullOrWhiteSpace(importInput))
        {
            return;
        }

        await RunBusyAsync(() =>
        {
            var imported = ClientRegistrationProtocol.ImportProfile(
                importInput,
                pendingRegistration);
            sessionStore.Save(imported);
            pendingStore.Delete();
            pendingRegistration = null;
            registrationRequest = string.Empty;
            ImportInput = string.Empty;
            session = imported;
            status = tunnelManager.GetStatus();
            RaiseState();
            return Task.CompletedTask;
        });
    }

    public async Task ConnectAsync()
    {
        if (isBusy || session is null)
        {
            return;
        }

        await RunBusyAsync(async () =>
        {
            var cached = session;
            _ = TunnelProfile.FromSession(cached, PreferredGatewayIndex(cached));
            sessionStore.Save(cached);
            status = TunnelConnectionStatus.Connecting;
            RaiseState();
            await tunnelManager.ConnectAsync().ConfigureAwait(true);
            status = tunnelManager.GetStatus();
            profileActivatedAt = DateTimeOffset.UtcNow;
            consecutiveProbeFailures = 0;
            try
            {
                var activeGateway = cached.SelectedGatewayNodeId;
                var refreshed = await controlPlane.RefreshAsync(cached).ConfigureAwait(true);
                if (activeGateway is not null
                    && GatewayIndex(refreshed, activeGateway) >= 0)
                {
                    refreshed.SelectedGatewayNodeId = activeGateway;
                }

                _ = TunnelProfile.FromSession(
                    refreshed,
                    PreferredGatewayIndex(refreshed));
                sessionStore.Save(refreshed);
                session = refreshed;
            }
            catch (ControlPlaneException)
            {
                session = cached;
            }

            RaiseState();
        });
    }

    public async Task DisconnectAsync()
    {
        if (isBusy)
        {
            return;
        }

        await RunBusyAsync(async () =>
        {
            status = TunnelConnectionStatus.Disconnecting;
            RaiseState();
            await tunnelManager.DisconnectAsync().ConfigureAwait(true);
            status = tunnelManager.GetStatus();
            consecutiveProbeFailures = 0;
            failedGateways.Clear();
            RaiseState();
        });
    }

    public async Task RefreshAsync()
    {
        if (isBusy || session is null || !IsConnected)
        {
            return;
        }

        await RunBusyAsync(async () =>
        {
            var activeGateway = session.SelectedGatewayNodeId;
            session = await controlPlane.RefreshAsync(session).ConfigureAwait(true);
            if (activeGateway is not null)
            {
                session.SelectedGatewayNodeId = activeGateway;
            }

            _ = TunnelProfile.FromSession(session, PreferredGatewayIndex(session));
            await ApplyPreferredGatewayAsync(
                session,
                status == TunnelConnectionStatus.Connected).ConfigureAwait(true);
            sessionStore.Save(session);
            RaiseState();
        });
    }

    public async Task RemoveAsync()
    {
        if (isBusy || session is null)
        {
            return;
        }

        await RunBusyAsync(async () =>
        {
            if (status == TunnelConnectionStatus.Connected)
            {
                await controlPlane.RemoveAsync(session).ConfigureAwait(true);
                await tunnelManager.DisconnectAsync().ConfigureAwait(true);
            }

            sessionStore.Delete();
            pendingStore.Delete();
            session = null;
            pendingRegistration = null;
            registrationRequest = string.Empty;
            ImportInput = string.Empty;
            status = tunnelManager.GetStatus();
            failedGateways.Clear();
            consecutiveProbeFailures = 0;
            RaiseState();
        });
    }

    public void OpenWebUi()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = HeteroNetworkConstants.OverlayWebUiUri.AbsoluteUri,
                UseShellExecute = true,
            });
        }
        catch (Exception error) when (error is InvalidOperationException or Win32Exception)
        {
            SetError(error.Message);
        }
    }

    public void ClearError() => SetError(null);

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        statusTimer.Stop();
        statusTimer.Tick -= StatusTimer_Tick;
        controlPlane.Dispose();
        backgroundGate.Dispose();
    }

    private async Task RestoreAsync()
    {
        try
        {
            session = sessionStore.Load();
            if (session is null)
            {
                pendingRegistration = pendingStore.Load();
                if (pendingRegistration is not null)
                {
                    registrationRequest = ClientRegistrationProtocol.RegistrationUri(
                        pendingRegistration.Bundle);
                }
            }
            else
            {
                pendingStore.Delete();
            }

            status = tunnelManager.GetStatus();
            if (status == TunnelConnectionStatus.Connected)
            {
                profileActivatedAt = DateTimeOffset.UtcNow;
            }
            RaiseState();
        }
        catch (Exception error)
        {
            SetError(error.Message);
        }

        await Task.CompletedTask;
    }

    private async void StatusTimer_Tick(object? sender, EventArgs e)
    {
        if (disposed || isBusy || !await backgroundGate.WaitAsync(0))
        {
            return;
        }

        try
        {
            status = tunnelManager.GetStatus();
            RaiseState();
            if (status != TunnelConnectionStatus.Connected || session is null)
            {
                return;
            }

            await RefreshConnectedSessionAsync(session);
        }
        catch (Exception error)
        {
            SetError(error.Message);
        }
        finally
        {
            backgroundGate.Release();
        }
    }

    private async Task RefreshConnectedSessionAsync(ClientSession current)
    {
        var activeGateway = current.SelectedGatewayNodeId
            ?? current.PeerMap.Peers.FirstOrDefault()?.NodeId;
        if (activeGateway is null)
        {
            throw new TunnelProfileException(
                "The client peer map does not contain a gateway.");
        }

        var activeIndex = GatewayIndex(current, activeGateway);
        if (activeIndex < 0)
        {
            activeIndex = 0;
        }

        var activeProfile = TunnelProfile.FromSession(current, activeIndex);
        var healthy = await tunnelManager.ProbeAsync(activeProfile).ConfigureAwait(true);
        if (healthy)
        {
            consecutiveProbeFailures = 0;
        }
        else if (DateTimeOffset.UtcNow - profileActivatedAt >= TimeSpan.FromSeconds(10))
        {
            consecutiveProbeFailures++;
            if (consecutiveProbeFailures >= GatewayFailureThreshold)
            {
                failedGateways[activeProfile.GatewayNodeId] =
                    DateTimeOffset.UtcNow + GatewayFailureCooldown;
                consecutiveProbeFailures = 0;
            }
        }

        current.SelectedGatewayNodeId = activeProfile.GatewayNodeId;
        try
        {
            session = await controlPlane.RefreshAsync(current).ConfigureAwait(true);
        }
        catch (ControlPlaneException)
        {
            session = current;
        }

        await ApplyPreferredGatewayAsync(session, true).ConfigureAwait(true);
        sessionStore.Save(session);
        RaiseState();
    }

    private async Task ApplyPreferredGatewayAsync(
        ClientSession current,
        bool reconnectIfChanged)
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var expired in failedGateways
                     .Where(item => item.Value <= now)
                     .Select(item => item.Key)
                     .ToArray())
        {
            failedGateways.Remove(expired);
        }

        var previous = current.SelectedGatewayNodeId;
        var preferredIndex = PreferredGatewayIndex(current);
        var preferred = TunnelProfile.FromSession(current, preferredIndex);
        current.SelectedGatewayNodeId = preferred.GatewayNodeId;
        if (reconnectIfChanged
            && previous is not null
            && preferred.GatewayNodeId != previous
            && status == TunnelConnectionStatus.Connected)
        {
            sessionStore.Save(current);
            status = TunnelConnectionStatus.Reconnecting;
            RaiseState();
            await tunnelManager.ConnectAsync().ConfigureAwait(true);
            status = tunnelManager.GetStatus();
            profileActivatedAt = DateTimeOffset.UtcNow;
            consecutiveProbeFailures = 0;
        }
    }

    private int PreferredGatewayIndex(ClientSession current)
    {
        for (var index = 0; index < current.PeerMap.Peers.Count; index++)
        {
            if (!failedGateways.ContainsKey(current.PeerMap.Peers[index].NodeId))
            {
                return index;
            }
        }

        if (current.SelectedGatewayNodeId is { } selected)
        {
            var selectedIndex = GatewayIndex(current, selected);
            if (selectedIndex >= 0)
            {
                return selectedIndex;
            }
        }

        return 0;
    }

    private static int GatewayIndex(ClientSession current, string nodeId)
    {
        for (var index = 0; index < current.PeerMap.Peers.Count; index++)
        {
            if (current.PeerMap.Peers[index].NodeId == nodeId)
            {
                return index;
            }
        }

        return -1;
    }

    private async Task RunBusyAsync(Func<Task> operation)
    {
        isBusy = true;
        SetError(null);
        RaiseState();
        try
        {
            await operation();
        }
        catch (Exception error)
        {
            status = tunnelManager.GetStatus();
            SetError(error.Message);
        }
        finally
        {
            isBusy = false;
            RaiseState();
        }
    }

    private void SetError(string? value)
    {
        lastError = value;
        OnPropertyChanged(nameof(LastError));
        OnPropertyChanged(nameof(HasError));
    }

    private void RaiseState()
    {
        OnPropertyChanged(nameof(IsConfigured));
        OnPropertyChanged(nameof(IsNotConfigured));
        OnPropertyChanged(nameof(IsBusy));
        OnPropertyChanged(nameof(HasPendingRegistration));
        OnPropertyChanged(nameof(CanGenerateRegistration));
        OnPropertyChanged(nameof(CanImport));
        OnPropertyChanged(nameof(CanRefresh));
        OnPropertyChanged(nameof(RegistrationRequest));
        OnPropertyChanged(nameof(ImportInput));
        OnPropertyChanged(nameof(WireGuardMissing));
        OnPropertyChanged(nameof(IsConnected));
        OnPropertyChanged(nameof(StatusDisplay));
        OnPropertyChanged(nameof(StatusBrush));
        OnPropertyChanged(nameof(ConnectionAction));
        OnPropertyChanged(nameof(VpnAddress));
        OnPropertyChanged(nameof(GatewayName));
        OnPropertyChanged(nameof(ClusterName));
        OnPropertyChanged(nameof(ClientId));
        OnPropertyChanged(nameof(LastRefresh));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
