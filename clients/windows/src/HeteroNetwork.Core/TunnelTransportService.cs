using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HeteroNetwork.Core;

internal sealed class TunnelTransportConfiguration
{
    [JsonPropertyName("client_node_id")] public string ClientNodeId { get; set; } = "";
    [JsonPropertyName("gateway_node_id")] public string GatewayNodeId { get; set; } = "";
    [JsonPropertyName("gateway_endpoint")] public string GatewayEndpoint { get; set; } = "";
    [JsonPropertyName("gateway_wireguard_public_key")] public string GatewayWireGuardPublicKey { get; set; } = "";
    [JsonPropertyName("gateway_http_tunnel_urls")] public IReadOnlyList<string> GatewayHttpTunnelUrls { get; set; } = [];
    [JsonPropertyName("private_key")] public string? PrivateKey { get; set; }
    [JsonPropertyName("proxy_url")] public string? ProxyUrl { get; set; }
}

// The OS service stays installed while the shared transport engine changes
// between UDP and HTTP(S). The child receives keys through a private pipe.
internal sealed class TunnelTransportService : IDisposable
{
    private readonly Process process;
    public string RuntimeConfigurationPath { get; }

    private TunnelTransportService(Process process, string path)
    {
        this.process = process;
        RuntimeConfigurationPath = path;
    }

    public static TunnelTransportService? Start(string configurationPath)
    {
        var encrypted = File.ReadAllBytes(configurationPath);
        var plaintext = WindowsDataProtection.UnprotectLocalMachine(encrypted);
        try
        {
            var text = Encoding.UTF8.GetString(plaintext);
            const string prefix = "# HeteroNetworkTransport = ";
            var metadataLine = text.Split('\n').FirstOrDefault(line => line.StartsWith(prefix, StringComparison.Ordinal));
            if (metadataLine is null) return null;
            var metadata = JsonSerializer.Deserialize<TunnelTransportConfiguration>(
                Convert.FromBase64String(metadataLine[prefix.Length..].Trim()))
                ?? throw new InvalidOperationException("Invalid transport configuration.");
            var keyLine = text.Split('\n').FirstOrDefault(line => line.TrimStart().StartsWith("PrivateKey = ", StringComparison.Ordinal))
                ?? throw new InvalidOperationException("Missing WireGuard key.");
            var key = Convert.FromBase64String(keyLine[(keyLine.IndexOf('=') + 1)..].Trim());
            try { metadata.PrivateKey = Convert.ToHexStringLower(key); }
            finally { CryptographicOperations.ZeroMemory(key); }
            var proxyPath = Path.Combine(AppContext.BaseDirectory, "HeteroNetwork.TransportProxy.exe");
            if (!File.Exists(proxyPath)) throw new InvalidOperationException("The HTTP transport runtime is missing.");
            var start = new ProcessStartInfo(proxyPath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            var process = Process.Start(start) ?? throw new InvalidOperationException("The transport runtime failed to start.");
            try
            {
                process.StandardInput.WriteLine(JsonSerializer.Serialize(metadata));
                process.StandardInput.Flush();
                metadata.PrivateKey = null;
                var line = process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
                using var ready = JsonDocument.Parse(line ?? "{}");
                var endpoint = ready.RootElement.GetProperty("endpoint").GetString();
                if (endpoint is null || !IPEndPoint.TryParse(endpoint, out var local) || !IPAddress.IsLoopback(local.Address) || local.Port == 0)
                    throw new InvalidOperationException("The transport runtime returned an invalid endpoint.");
                var originalEndpoint = "Endpoint = " + metadata.GatewayEndpoint;
                if (!text.Contains(originalEndpoint, StringComparison.Ordinal))
                    throw new InvalidOperationException("The gateway endpoint does not match the transport configuration.");
                var runtimeText = text.Replace(originalEndpoint, "Endpoint = " + local, StringComparison.Ordinal);
                var directory = Path.Combine(Path.GetDirectoryName(configurationPath)!, "runtime");
                Directory.CreateDirectory(directory);
                // Keep the same basename for WireGuard's existing service and
                // adapter identity; the canonical file retains its original
                // configuration so reconnect checks do not reinstall it.
                var runtimePath = Path.Combine(directory, Path.GetFileName(configurationPath));
                var runtimeBytes = Encoding.UTF8.GetBytes(runtimeText);
                try { File.WriteAllBytes(runtimePath, WindowsDataProtection.ProtectLocalMachine(runtimeBytes)); }
                finally { CryptographicOperations.ZeroMemory(runtimeBytes); }
                return new TunnelTransportService(process, runtimePath);
            }
            catch
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                process.Dispose();
                throw;
            }
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public void Dispose()
    {
        try { process.StandardInput.Close(); }
        catch (IOException) { }
        if (!process.HasExited && !process.WaitForExit(2000)) process.Kill(entireProcessTree: true);
        process.Dispose();
        try { File.Delete(RuntimeConfigurationPath); }
        catch (IOException) { }
    }
}
