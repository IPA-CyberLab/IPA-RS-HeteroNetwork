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
    private readonly ControlPlaneClient controlPlane = new();
    private readonly WindowsTunnelManager tunnelManager;
    private readonly DispatcherTimer statusTimer;
    private readonly SemaphoreSlim backgroundGate = new(1, 1);
    private readonly Dictionary<string, DateTimeOffset> failedGateways = [];
    private ClientSession? session;
    private TunnelConnectionStatus status;
    private bool isBusy;
    private string enrollmentInput = string.Empty;
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
    public bool CanEnroll => !isBusy && !string.IsNullOrWhiteSpace(enrollmentInput);
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

    public void SetEnrollmentInput(string value)
    {
        enrollmentInput = value;
        OnPropertyChanged(nameof(CanEnroll));
    }

    public void AcceptActivation(string value)
    {
        if (!value.StartsWith("heteronetwork://", StringComparison.OrdinalIgnoreCase))
        {
            SetError("The activation link is invalid.");
            return;
        }

        enrollmentInput = value;
        ActivationAccepted?.Invoke(this, value);
        OnPropertyChanged(nameof(CanEnroll));
    }

    public async Task EnrollAsync()
    {
        if (isBusy || string.IsNullOrWhiteSpace(enrollmentInput))
        {
            return;
        }

        await RunBusyAsync(async () =>
        {
            var token = EnrollmentParser.Parse(enrollmentInput);
            var joined = await controlPlane.JoinAsync(
                token,
                ClientKeyMaterial.Generate()).ConfigureAwait(true);
            _ = TunnelProfile.FromSession(joined);
            sessionStore.Save(joined);
            session = joined;
            enrollmentInput = string.Empty;
            RaiseState();
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
            session = await controlPlane.RefreshAsync(session).ConfigureAwait(true);
            _ = TunnelProfile.FromSession(session);
            sessionStore.Save(session);
            status = TunnelConnectionStatus.Connecting;
            RaiseState();
            await tunnelManager.ConnectAsync().ConfigureAwait(true);
            status = tunnelManager.GetStatus();
            profileActivatedAt = DateTimeOffset.UtcNow;
            consecutiveProbeFailures = 0;
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
        if (isBusy || session is null)
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
            if (status != TunnelConnectionStatus.Disconnected
                && status != TunnelConnectionStatus.NotConfigured)
            {
                await tunnelManager.DisconnectAsync().ConfigureAwait(true);
            }

            await controlPlane.RemoveAsync(session).ConfigureAwait(true);
            sessionStore.Delete();
            session = null;
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
        OnPropertyChanged(nameof(CanEnroll));
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
