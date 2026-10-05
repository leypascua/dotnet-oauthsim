using System.Text.Json.Serialization;

namespace OAuthSim.Web.Models;

public sealed record JsonWebKeySet([property: JsonPropertyName("keys")] IReadOnlyList<RsaJsonWebKey> Keys);

public sealed record RsaJsonWebKey
{
    [JsonPropertyName("kty")]
    public string KeyType { get; init; } = "RSA";

    [JsonPropertyName("use")]
    public string Use { get; init; } = "sig";

    [JsonPropertyName("alg")]
    public string Algorithm { get; init; } = "RS256";

    [JsonPropertyName("kid")]
    public required string KeyId { get; init; }

    [JsonPropertyName("n")]
    public required string Modulus { get; init; }

    [JsonPropertyName("e")]
    public required string Exponent { get; init; }
}
