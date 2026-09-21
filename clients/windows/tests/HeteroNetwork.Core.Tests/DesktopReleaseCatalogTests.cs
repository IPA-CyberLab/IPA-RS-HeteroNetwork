using System.Text;
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

    [Fact]
    public void AtomFallbackSelectsNewestReleaseAndBuildsTrustedUrls()
    {
        var feed = AtomFeed(
            AtomEntry("v1.2.0", "2026-09-20T00:00:00Z"),
            AtomEntry("v1.3.0", "2026-09-21T00:00:00Z"));

        var update = Assert.IsType<DesktopReleaseUpdate>(
            DesktopReleaseCatalog.AvailableUpdateFromAtom(feed, "v1.2.0"));

        Assert.Equal("v1.3.0", update.Tag);
        Assert.Equal(Asset, update.AssetName);
        Assert.Equal(DownloadUrl("v1.3.0", Asset), update.ArchiveUrl.AbsoluteUri);
        Assert.Equal(
            DownloadUrl("v1.3.0", $"{Asset}.sha256"),
            update.ChecksumUrl.AbsoluteUri);
    }

    [Fact]
    public void AtomFallbackDoesNotDowngradeNewerInstalledRelease()
    {
        var feed = AtomFeed(
            AtomEntry("v2.0.0", "2026-09-21T00:00:00Z"),
            AtomEntry("v1.9.0", "2026-09-20T00:00:00Z"));

        Assert.Null(DesktopReleaseCatalog.AvailableUpdateFromAtom(feed, "v2.0.0"));
    }

    [Fact]
    public void AtomFallbackIgnoresUntrustedAndUnsafeReleaseLinks()
    {
        var feed = AtomFeed(
            AtomEntry(
                "v9.0.0",
                "2026-09-22T00:00:00Z",
                "https://example.com/IPA-CyberLab/IPA-RS-HeteroNetwork/releases/tag/v9.0.0"),
            AtomEntry(
                "unsafe",
                "2026-09-21T00:00:00Z",
                "https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/releases/tag/not-a-release"),
            AtomEntry("v1.2.0", "2026-09-20T00:00:00Z"));

        var update = Assert.IsType<DesktopReleaseUpdate>(
            DesktopReleaseCatalog.AvailableUpdateFromAtom(feed, "v1.1.0"));
        Assert.Equal("v1.2.0", update.Tag);
    }

    [Theory]
    [InlineData("<feed><entry>")]
    [InlineData("<!DOCTYPE feed [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><feed>&xxe;</feed>")]
    public void AtomFallbackRejectsMalformedOrDtdFeeds(string feed)
    {
        Assert.Throws<DesktopReleaseCatalogException>(() =>
            DesktopReleaseCatalog.AvailableUpdateFromAtom(
                Encoding.UTF8.GetBytes(feed),
                "v1.0.0"));
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

    private static byte[] AtomFeed(params string[] entries) => Encoding.UTF8.GetBytes($$"""
        <?xml version="1.0" encoding="UTF-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
          {{string.Join("\n", entries)}}
        </feed>
        """);

    private static string AtomEntry(
        string tag,
        string updated,
        string? href = null) => $$"""
        <entry>
          <updated>{{updated}}</updated>
          <link rel="alternate" href="{{href ?? $"https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/releases/tag/{tag}"}}" />
        </entry>
        """;
}
