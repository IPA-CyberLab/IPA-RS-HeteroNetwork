using System.Text.Json;
using HeteroNetwork.Core;

namespace HeteroNetwork.Core.Tests;

public sealed class DesktopReleaseCatalogTests
{
    private const string Asset = DesktopReleaseCatalog.WindowsAssetName;

    [Fact]
    public void SelectsNewestCompletePublishedRelease()
    {
        var catalog = Catalog(
            Release("v1.2.0", "2026-09-20T00:00:00Z", assets: [Asset, $"{Asset}.sha256"]),
            Release("v1.3.0", "2026-09-21T00:00:00Z", draft: true, assets: [Asset, $"{Asset}.sha256"]),
            Release("v1.1.0", "2026-09-19T00:00:00Z", assets: [Asset, $"{Asset}.sha256"]));

        var update = Assert.IsType<DesktopReleaseUpdate>(
            DesktopReleaseCatalog.AvailableUpdate(catalog, "v1.1.0"));

        Assert.Equal("v1.2.0", update.Tag);
        Assert.Equal(Asset, update.AssetName);
        Assert.Equal(
            $"https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/releases/download/v1.2.0/{Asset}",
            update.ArchiveUrl.AbsoluteUri);
    }

    [Fact]
    public void DoesNotDowngradeAReleaseWithNewerPublicationTime()
    {
        var catalog = Catalog(
            Release("v2.0.0", "2026-09-21T00:00:00Z", assets: []),
            Release("v1.9.0", "2026-09-20T00:00:00Z", assets: [Asset, $"{Asset}.sha256"]));

        Assert.Null(DesktopReleaseCatalog.AvailableUpdate(catalog, "v2.0.0"));
    }

    [Fact]
    public void RejectsAssetsHostedOutsideTheExpectedReleasePath()
    {
        var release = new
        {
            tag_name = "v1.2.0",
            published_at = "2026-09-20T00:00:00Z",
            draft = false,
            assets = new[]
            {
                new
                {
                    name = Asset,
                    browser_download_url = $"https://example.com/{Asset}",
                },
                new
                {
                    name = $"{Asset}.sha256",
                    browser_download_url = DownloadUrl("v1.2.0", $"{Asset}.sha256"),
                },
            },
        };

        Assert.Null(DesktopReleaseCatalog.AvailableUpdate(
            JsonSerializer.SerializeToUtf8Bytes(new[] { release }),
            "v1.1.0"));
    }

    [Fact]
    public void ReturnsNoUpdateForDevelopmentOrCurrentRelease()
    {
        var catalog = Catalog(
            Release("v1.2.0", "2026-09-20T00:00:00Z", assets: [Asset, $"{Asset}.sha256"]));

        Assert.Null(DesktopReleaseCatalog.AvailableUpdate(catalog, "development"));
        Assert.Null(DesktopReleaseCatalog.AvailableUpdate(catalog, "v1.2.0"));
    }

    [Fact]
    public void RejectsMalformedCatalogs()
    {
        Assert.Throws<DesktopReleaseCatalogException>(() =>
            DesktopReleaseCatalog.AvailableUpdate("{"u8, "v1.0.0"));
    }

    private static byte[] Catalog(params object[] releases) =>
        JsonSerializer.SerializeToUtf8Bytes(releases);

    private static object Release(
        string tag,
        string publishedAt,
        bool draft = false,
        string[]? assets = null) => new
        {
            tag_name = tag,
            published_at = publishedAt,
            draft,
            assets = (assets ?? []).Select(name => new
            {
                name,
                browser_download_url = DownloadUrl(tag, name),
            }),
        };

    private static string DownloadUrl(string tag, string name) =>
        $"https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/releases/download/{tag}/{name}";
}
