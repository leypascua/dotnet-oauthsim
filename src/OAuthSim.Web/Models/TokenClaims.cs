using System.Collections.Frozen;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OAuthSim.Web.Models;

// NumericDate claims retain their JWT representation: Unix time seconds.
public sealed record JwtClaims
{
    public string? Issuer { get; init; }
    public string? Subject { get; init; }
    public TokenAudience? Audience { get; init; }
    public long? ExpiresAt { get; init; }
    public long? IssuedAt { get; init; }
    public long? NotBefore { get; init; }
    public string? TokenId { get; init; }
}

public sealed record AccessTokenClaims
{
    public string? ClientId { get; init; }
    public string? Scope { get; init; }
}

public sealed record OidcAuthenticationClaims
{
    public string? Nonce { get; init; }
    public long? AuthTime { get; init; }
    public string? AccessTokenHash { get; init; }
}

public sealed record OidcProfileClaims
{
    public string? Email { get; init; }
    public string? Name { get; init; }
    public string? Locale { get; init; }
}

// These are simulator conventions, not registered JWT or OIDC claims.
public sealed record SimulatorClaims
{
    public string? TokenUse { get; init; }
    public string? GrantType { get; init; }
    public string? Country { get; init; }
    public string? Language { get; init; }
}

[JsonConverter(typeof(TokenPayloadJsonConverter))]
public sealed record TokenPayload
{
    private readonly IReadOnlyDictionary<string, JsonElement> customClaims = FrozenDictionary<string, JsonElement>.Empty;

    public JwtClaims Jwt { get; init; } = new();
    public AccessTokenClaims Access { get; init; } = new();
    public OidcAuthenticationClaims Authentication { get; init; } = new();
    public OidcProfileClaims Profile { get; init; } = new();
    public SimulatorClaims Simulator { get; init; } = new();
    public IReadOnlyDictionary<string, JsonElement> CustomClaims
    {
        get => customClaims;
        init => customClaims = value.Where(c => !TokenPayloadJsonConverter.KnownClaims.Contains(c.Key))
            .ToFrozenDictionary(c => c.Key, c => c.Value.Clone(), StringComparer.Ordinal);
    }

    // Retain explicit JSON nulls separately from absent optional properties.
    internal IReadOnlySet<string> ExplicitNullClaims { get; init; } = FrozenSet<string>.Empty;

    public IReadOnlyDictionary<string, JsonElement> ToClaims() => JsonSerializer.SerializeToElement(this)
        .EnumerateObject().ToFrozenDictionary(p => p.Name, p => p.Value, StringComparer.Ordinal);
}
