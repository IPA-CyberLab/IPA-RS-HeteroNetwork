using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Windows;
using HeteroNetwork.Core;
using Microsoft.Win32;

namespace HeteroNetwork.App;

public partial class App : System.Windows.Application
{
    private const string MutexName = @"Local\HeteroNetwork.Windows.App.v1";
    private const string PipeName = "HeteroNetwork.Windows.Activation.v1";
    private Mutex? instanceMutex;
    private CancellationTokenSource? activationCancellation;
    private MainWindow? mainWindow;
    private bool exiting;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var helper = e.Args.FirstOrDefault();
        if (helper == "--wireguard-self-test")
        {
            try
            {
                EmbeddedWireGuardRuntime.SelfTest();
                Shutdown(0);
            }
            catch
            {
                Shutdown(1);
            }

            return;
        }

        if (helper == "/service")
        {
            var configurationPath = e.Args.ElementAtOrDefault(1);
            if (configurationPath is null)
            {
                Shutdown(2);
                return;
            }

            try
            {
                Shutdown(EmbeddedWireGuardRuntime.RunTunnelService(configurationPath));
            }
            catch
            {
                Shutdown(1);
            }

            return;
        }

        if (helper is "--tunnel-connect" or "--tunnel-disconnect")
        {
            var result = await new WindowsTunnelManager().RunHelperAsync(helper);
            Shutdown(result);
            return;
        }

        instanceMutex = new Mutex(true, MutexName, out var ownsMutex);
        if (!ownsMutex)
        {
            await ForwardActivationAsync(e.Args.FirstOrDefault());
            Shutdown();
            return;
        }

        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        RegisterUrlProtocol();
        var viewModel = new MainViewModel();
        mainWindow = new MainWindow(viewModel);
        MainWindow = mainWindow;
        mainWindow.Show();
        if (e.Args.FirstOrDefault() is { } activation)
        {
            viewModel.AcceptActivation(activation);
        }

        activationCancellation = new CancellationTokenSource();
        _ = ListenForActivationsAsync(viewModel, activationCancellation.Token);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        exiting = true;
        activationCancellation?.Cancel();
        if (mainWindow?.DataContext is IDisposable disposable)
        {
            disposable.Dispose();
        }

        mainWindow?.DisposeTrayIcon();
        instanceMutex?.Dispose();
        base.OnExit(e);
    }

    public void ExitApplication()
    {
        exiting = true;
        mainWindow?.Close();
        Shutdown();
    }

    public bool IsExiting => exiting;

    private async Task ListenForActivationsAsync(
        MainViewModel viewModel,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.In,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);
                await server.WaitForConnectionAsync(cancellationToken);
                using var reader = new StreamReader(
                    server,
                    Encoding.UTF8,
                    false,
                    4096,
                    leaveOpen: true);
                var activation = await reader.ReadLineAsync(cancellationToken);
                await Dispatcher.InvokeAsync(() =>
                {
                    if (!string.IsNullOrWhiteSpace(activation))
                    {
                        viewModel.AcceptActivation(activation);
                    }

                    mainWindow?.ShowAndActivate();
                });
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (IOException)
            {
                await Task.Delay(250, cancellationToken);
            }
        }
    }

    private static async Task ForwardActivationAsync(string? activation)
    {
        try
        {
            await using var client = new NamedPipeClientStream(
                ".",
                PipeName,
                PipeDirection.Out,
                PipeOptions.Asynchronous);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await client.ConnectAsync(timeout.Token);
            await using var writer = new StreamWriter(client, new UTF8Encoding(false))
            {
                AutoFlush = true,
            };
            await writer.WriteLineAsync(activation ?? string.Empty);
        }
        catch (Exception error) when (error is IOException or OperationCanceledException)
        {
            // The existing process may be between startup and pipe creation. Its
            // window remains the authoritative instance.
        }
    }

    private static void RegisterUrlProtocol()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
        {
            return;
        }

        try
        {
            using var scheme = Registry.CurrentUser.CreateSubKey(
                @"Software\Classes\heteronetwork");
            scheme.SetValue(null, "URL:HeteroNetwork Enrollment Protocol");
            scheme.SetValue("URL Protocol", string.Empty);
            using var icon = scheme.CreateSubKey("DefaultIcon");
            icon.SetValue(null, $"\"{executable}\",0");
            using var command = scheme.CreateSubKey(@"shell\open\command");
            command.SetValue(null, $"\"{executable}\" \"%1\"");
        }
        catch (UnauthorizedAccessException)
        {
            // Pasting the link into the app remains available.
        }
    }
}
