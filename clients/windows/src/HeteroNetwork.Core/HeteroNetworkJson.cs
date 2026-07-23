using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HeteroNetwork.Core;

public static class HeteroNetworkJson
{
    private static readonly JsonSerializerOptions OptionsValue = CreateOptions();

    public static JsonSerializerOptions Options => OptionsValue;

    public static DateTimeOffset ParseRfc3339(string value)
    {
        if (!DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            throw new JsonException($"Invalid RFC 3339 timestamp: {value}");
        }

        return parsed;
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            WriteIndented = false,
        };
        options.Converters.Add(new Rfc3339DateTimeOffsetConverter());
        return options;
    }
}

internal sealed class Rfc3339DateTimeOffsetConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        var value = reader.GetString() ?? throw new JsonException("A timestamp is required.");
        return HeteroNetworkJson.ParseRfc3339(value);
    }

    public override void Write(
        Utf8JsonWriter writer,
        DateTimeOffset value,
        JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.UtcDateTime.ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture));
    }
}
