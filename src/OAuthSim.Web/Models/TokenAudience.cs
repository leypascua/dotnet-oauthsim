using System.Text.Json;
using System.Text.Json.Serialization;

namespace OAuthSim.Web.Models;

// JWT audiences are identifiers, compared exactly; order does not affect membership.
[JsonConverter(typeof(TokenAudienceJsonConverter))]
public sealed class TokenAudience : IEquatable<TokenAudience>
{
    public IReadOnlyList<string> Values { get; }
    public bool IsValid => Values.Count > 0 && Values.All(v => !string.IsNullOrWhiteSpace(v));

    public TokenAudience(IEnumerable<string> values) => Values = Array.AsReadOnly(values.Distinct(StringComparer.Ordinal).ToArray());
    public bool Contains(string value) => Values.Contains(value, StringComparer.Ordinal);
    public TokenAudience? Normalize()
    {
        var values = Values.Select(v => v.Trim()).Where(v => v.Length > 0).ToArray();
        return values.Length == 0 ? null : new(values);
    }
    public bool Equals(TokenAudience? other) => other is not null && Values.Count == other.Values.Count && Values.All(other.Contains);
    public override bool Equals(object? obj) => obj is TokenAudience other && Equals(other);
    public override int GetHashCode() => Values.Aggregate(0, (hash, value) => hash ^ StringComparer.Ordinal.GetHashCode(value));
    public override string ToString() => string.Join(", ", Values);
    public static implicit operator TokenAudience?(string? value) => value is null ? null : new([value]);
    public static bool operator ==(TokenAudience? left, TokenAudience? right) => ReferenceEquals(left, right) || left is not null && left.Equals(right);
    public static bool operator !=(TokenAudience? left, TokenAudience? right) => !(left == right);
}

public sealed class TokenAudienceJsonConverter : JsonConverter<TokenAudience>
{
    public override TokenAudience Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        var value = document.RootElement;
        if (value.ValueKind == JsonValueKind.String) return new([value.GetString()!]);
        if (value.ValueKind != JsonValueKind.Array || value.EnumerateArray().Any(v => v.ValueKind != JsonValueKind.String))
            throw new JsonException("Audience must be a string or an array of strings.");
        return new(value.EnumerateArray().Select(v => v.GetString()!));
    }

    public override void Write(Utf8JsonWriter writer, TokenAudience value, JsonSerializerOptions options)
    {
        if (value.Values.Count == 1) writer.WriteStringValue(value.Values[0]);
        else
        {
            writer.WriteStartArray();
            foreach (var audience in value.Values) writer.WriteStringValue(audience);
            writer.WriteEndArray();
        }
    }
}
