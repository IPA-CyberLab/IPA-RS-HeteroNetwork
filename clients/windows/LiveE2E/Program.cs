using System.Text;
using System.Text.Json;
using HeteroNetwork.Core;

return await LiveE2E.RunAsync(args);

internal static class LiveE2E
{
    private static readonly UTF8Encoding Utf8 = new(false);

    public static async Task<int> RunAsync(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The live client driver requires Windows.");
        }

        if (args.Length != 2 || string.IsNullOrWhiteSpace(args[1]))
        {
            throw new ArgumentException(
                "Usage: HeteroNetwork.Windows.LiveE2E <prepare|import|remove> <path>");
        }

        switch (args[0])
        {
            case "prepare":
                Prepare(Path.GetFullPath(args[1]));
                return 0;
            case "import":
                Import(Path.GetFullPath(args[1]));
                return 0;
            case "remove":
                await RemoveAsync(Path.GetFullPath(args[1])).ConfigureAwait(false);
                return 0;
            default:
                throw new ArgumentException("The live client driver command is invalid.");
        }
    }

    private static void Prepare(string requestPath)
    {
        var sessionStore = new ClientSessionStore();
        var pendingStore = new PendingClientRegistrationStore();
        if (sessionStore.Load() is not null || pendingStore.Load() is not null)
        {
            throw new InvalidOperationException(
                "The Windows runner contains an existing HeteroNetwork identity.");
        }

        var pending = ClientRegistrationProtocol.GenerateRequest();
        pendingStore.Save(pending);
        WritePrivateFile(
            requestPath,
            ClientRegistrationProtocol.RegistrationUri(pending.Bundle));
    }

    private static void Import(string importPath)
    {
        var pendingStore = new PendingClientRegistrationStore();
        var pending = pendingStore.Load()
            ?? throw new InvalidOperationException("No pending registration is available.");
        var importUri = File.ReadAllText(importPath, Utf8).Trim();
        var session = ClientRegistrationProtocol.ImportProfile(importUri, pending);
        new ClientSessionStore().Save(session);
        pendingStore.Delete();
        WriteReport(importPath + ".report.json", session, "imported");
    }

    private static async Task RemoveAsync(string reportPath)
    {
        var sessionStore = new ClientSessionStore();
        var session = sessionStore.Load();
        if (session is null)
        {
            WritePrivateFile(
                reportPath,
                JsonSerializer.Serialize(new { result = "already_removed" }));
            return;
        }

        using var controlPlane = new ControlPlaneClient();
        await controlPlane.RemoveAsync(session).ConfigureAwait(false);
        WriteReport(reportPath, session, "removed");
        sessionStore.Delete();
        new PendingClientRegistrationStore().Delete();
    }

    private static void WriteReport(string path, ClientSession session, string result)
    {
        var gateways = session.PeerMap.Peers
            .Select(peer => new { node_id = peer.NodeId, vpn_ip = peer.VpnIp })
            .ToArray();
        var report = JsonSerializer.Serialize(new
        {
            result,
            client_id = session.Client.NodeId,
            client_vpn_ip = session.Client.VpnIp,
            selected_gateway_node_id = session.SelectedGatewayNodeId,
            gateways,
        });
        WritePrivateFile(path, report);
    }

    private static void WritePrivateFile(string path, string value)
    {
        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException("The output path has no parent directory.");
        Directory.CreateDirectory(directory);
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough);
        using var writer = new StreamWriter(stream, Utf8);
        writer.Write(value);
        writer.Write('\n');
        writer.Flush();
        stream.Flush(true);
    }
}
