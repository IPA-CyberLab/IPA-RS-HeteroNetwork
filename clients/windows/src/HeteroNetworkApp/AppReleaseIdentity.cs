using System.Reflection;
using HeteroNetwork.Core;

namespace HeteroNetwork.App;

internal static class AppReleaseIdentity
{
    private const string MetadataName = "HeteroNetworkReleaseTag";

    public static string CurrentTag { get; } = ReadCurrentTag();

    public static bool AutomaticUpdatesEnabled =>
        DesktopReleaseCatalog.IsSafeReleaseTag(CurrentTag);

    private static string ReadCurrentTag()
    {
        var assembly = Assembly.GetEntryAssembly();
        var value = assembly?
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute =>
                string.Equals(attribute.Key, MetadataName, StringComparison.Ordinal))
            ?.Value;
        return string.IsNullOrWhiteSpace(value) ? "development" : value;
    }
}
