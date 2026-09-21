using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml;
using System.Xml.Linq;

namespace HeteroNetwork.Core;

public sealed record DesktopReleaseUpdate(
    string Tag,
    string AssetName,
    Uri ArchiveUrl,
    Uri ChecksumUrl);

public sealed class DesktopReleaseCatalogException : Exception
{
    public DesktopReleaseCatalogException(string message)
        : base(message)
    {
    }

    public DesktopReleaseCatalogException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public static class DesktopReleaseCatalog
{
    private const string RepositoryOwner = "IPA-CyberLab";
    private const string RepositoryName = "IPA-RS-HeteroNetwork";
    public const string WindowsAssetName = "heteronetwork-client-windows-x64.zip";

    public static DesktopReleaseUpdate? AvailableUpdate(
        ReadOnlySpan<byte> data,
        string currentTag,
        string assetName = WindowsAssetName)
    {
        if (!IsSafeReleaseTag(currentTag)
            || !string.Equals(assetName, WindowsAssetName, StringComparison.Ordinal))
        {
            return null;
        }

        GitHubRelease[] releases;
        try
        {
            releases = JsonSerializer.Deserialize<GitHubRelease[]>(data)
                ?? throw new JsonException("The release catalog was null.");
        }
        catch (JsonException error)
        {
            throw new DesktopReleaseCatalogException(
                "GitHub returned an invalid desktop release catalog.",
                error);
        }

        var candidates = new List<Candidate>();
        foreach (var release in releases)
        {
            if (release.Draft
                || !IsSafeReleaseTag(release.TagName)
                || !TryParseTimestamp(release.PublishedAt, out var publishedAt)
                || release.Assets is null)
            {
                continue;
            }

            var archive = release.Assets.FirstOrDefault(item =>
                string.Equals(item.Name, assetName, StringComparison.Ordinal));
            var checksumName = $"{assetName}.sha256";
            var checksum = release.Assets.FirstOrDefault(item =>
                string.Equals(item.Name, checksumName, StringComparison.Ordinal));
            if (archive?.BrowserDownloadUrl is null
                || checksum?.BrowserDownloadUrl is null
                || !IsExpectedDownloadUrl(
                    archive.BrowserDownloadUrl,
                    release.TagName!,
                    assetName)
                || !IsExpectedDownloadUrl(
                    checksum.BrowserDownloadUrl,
                    release.TagName!,
                    checksumName))
            {
                continue;
            }

            candidates.Add(new Candidate(
                release.TagName!,
                publishedAt,
                archive.BrowserDownloadUrl,
                checksum.BrowserDownloadUrl));
        }

        var newest = candidates
            .OrderByDescending(candidate => candidate.PublishedAt)
            .ThenByDescending(candidate => candidate.Tag, StringComparer.Ordinal)
            .FirstOrDefault();
        if (newest is null
            || string.Equals(newest.Tag, currentTag, StringComparison.Ordinal))
        {
            return null;
        }

        var current = releases.FirstOrDefault(release =>
            !release.Draft
            && string.Equals(release.TagName, currentTag, StringComparison.Ordinal));
        if (current is not null
            && TryParseTimestamp(current.PublishedAt, out var currentPublishedAt)
            && currentPublishedAt >= newest.PublishedAt)
        {
            return null;
        }

        return new DesktopReleaseUpdate(
            newest.Tag,
            assetName,
            newest.ArchiveUrl,
            newest.ChecksumUrl);
    }

    /// <summary>
    /// Selects an update from GitHub's public releases Atom feed when the
    /// unauthenticated API quota is unavailable. Asset names stay fixed by the
    /// release contract and the caller still verifies the published checksum.
    /// </summary>
    public static DesktopReleaseUpdate? AvailableUpdateFromAtom(
        ReadOnlySpan<byte> data,
        string currentTag,
        string assetName = WindowsAssetName)
    {
        if (!IsSafeReleaseTag(currentTag)
            || !string.Equals(assetName, WindowsAssetName, StringComparison.Ordinal))
        {
            return null;
        }

        XDocument document;
        try
        {
            using var stream = new MemoryStream(data.ToArray(), writable: false);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                IgnoreComments = true,
                IgnoreProcessingInstructions = true,
            });
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (XmlException error)
        {
            throw new DesktopReleaseCatalogException(
                "GitHub returned an invalid desktop release feed.",
                error);
        }

        XNamespace atom = "http://www.w3.org/2005/Atom";
        if (document.Root?.Name != atom + "feed")
        {
            throw new DesktopReleaseCatalogException(
                "GitHub returned an invalid desktop release feed.");
        }

        var candidates = new List<Candidate>();
        foreach (var entry in document.Root.Elements(atom + "entry"))
        {
            var updated = entry.Element(atom + "updated")?.Value;
            var alternate = entry.Elements(atom + "link")
                .FirstOrDefault(link =>
                    string.Equals(
                        (string?)link.Attribute("rel"),
                        "alternate",
                        StringComparison.OrdinalIgnoreCase));
            if (!TryParseTimestamp(updated, out var publishedAt)
                || !Uri.TryCreate(
                    (string?)alternate?.Attribute("href"),
                    UriKind.Absolute,
                    out var releasePage)
                || ReleaseTagFromPageUrl(releasePage) is not { } tag)
            {
                continue;
            }

            var archiveUrl = ExpectedDownloadUrl(tag, assetName);
            var checksumUrl = ExpectedDownloadUrl(tag, $"{assetName}.sha256");
            candidates.Add(new Candidate(
                tag,
                publishedAt,
                archiveUrl,
                checksumUrl));
        }

        var newest = candidates
            .OrderByDescending(candidate => candidate.PublishedAt)
            .ThenByDescending(candidate => candidate.Tag, StringComparer.Ordinal)
            .FirstOrDefault();
        if (newest is null
            || string.Equals(newest.Tag, currentTag, StringComparison.Ordinal))
        {
            return null;
        }

        var current = candidates.FirstOrDefault(candidate =>
            string.Equals(candidate.Tag, currentTag, StringComparison.Ordinal));
        if (current is not null && current.PublishedAt >= newest.PublishedAt)
        {
            return null;
        }

        return new DesktopReleaseUpdate(
            newest.Tag,
            assetName,
            newest.ArchiveUrl,
            newest.ChecksumUrl);
    }

    public static bool IsSafeReleaseTag(string? value)
    {
        if (string.IsNullOrEmpty(value)
            || value.Length < 2
            || value[0] != 'v'
            || !char.IsAsciiDigit(value[1]))
        {
            return false;
        }

        return value.All(character =>
            char.IsAsciiLetterOrDigit(character)
            || character is '.' or '_' or '-');
    }

    private static bool TryParseTimestamp(
        string? value,
        out DateTimeOffset timestamp) =>
        DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out timestamp);

    private static bool IsExpectedDownloadUrl(Uri url, string tag, string assetName)
    {
        var expectedPath = $"/{RepositoryOwner}/{RepositoryName}/releases/download/{tag}/{assetName}";
        return url.IsAbsoluteUri
            && string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && string.Equals(url.Host, "github.com", StringComparison.OrdinalIgnoreCase)
            && url.IsDefaultPort
            && string.IsNullOrEmpty(url.UserInfo)
            && string.IsNullOrEmpty(url.Query)
            && string.IsNullOrEmpty(url.Fragment)
            && string.Equals(url.AbsolutePath, expectedPath, StringComparison.Ordinal);
    }

    private static string? ReleaseTagFromPageUrl(Uri url)
    {
        var prefix = $"/{RepositoryOwner}/{RepositoryName}/releases/tag/";
        if (!url.IsAbsoluteUri
            || !string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(url.Host, "github.com", StringComparison.OrdinalIgnoreCase)
            || !url.IsDefaultPort
            || !string.IsNullOrEmpty(url.UserInfo)
            || !string.IsNullOrEmpty(url.Query)
            || !string.IsNullOrEmpty(url.Fragment)
            || !url.AbsolutePath.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }

        var tag = url.AbsolutePath[prefix.Length..];
        return IsSafeReleaseTag(tag) ? tag : null;
    }

    private static Uri ExpectedDownloadUrl(string tag, string assetName) =>
        new($"https://github.com/{RepositoryOwner}/{RepositoryName}/releases/download/{tag}/{assetName}");

    private sealed record GitHubRelease(
        [property: JsonPropertyName("tag_name")] string? TagName,
        [property: JsonPropertyName("published_at")] string? PublishedAt,
        [property: JsonPropertyName("draft")] bool Draft,
        [property: JsonPropertyName("assets")] GitHubReleaseAsset[]? Assets);

    private sealed record GitHubReleaseAsset(
        [property: JsonPropertyName("name")] string? Name,
        [property: JsonPropertyName("browser_download_url")] Uri? BrowserDownloadUrl);

    private sealed record Candidate(
        string Tag,
        DateTimeOffset PublishedAt,
        Uri ArchiveUrl,
        Uri ChecksumUrl);
}
