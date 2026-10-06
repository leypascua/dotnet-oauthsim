using System.Collections.Frozen;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OAuthSim.Web.Models;

// The C# groups are serialized as flat JWT claims, never nested JSON objects.
public sealed class TokenPayloadJsonConverter : JsonConverter<TokenPayload>
{
    internal static readonly FrozenSet<string> KnownClaims = new[]
    {
        "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "client_id", "scope",
        "nonce", "auth_time", "at_hash", "email", "name", "locale",
        "token_use", "grant_type", "country", "language"
    }.ToFrozenSet(StringComparer.Ordinal);

    public override TokenPayload Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException("Token claims must be an object.");
        var jwt = new JwtClaims();
        var access = new AccessTokenClaims();
        var authentication = new OidcAuthenticationClaims();
        var profile = new OidcProfileClaims();
        var simulator = new SimulatorClaims();
        var custom = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        var nulls = new HashSet<string>(StringComparer.Ordinal);
        foreach (var claim in document.RootElement.EnumerateObject())
        {
            var value = claim.Value;
            if (KnownClaims.Contains(claim.Name))
            {
                if (value.ValueKind == JsonValueKind.Null) nulls.Add(claim.Name);
                else nulls.Remove(claim.Name);
            }
            switch (claim.Name)
            {
                case "iss": jwt = jwt with { Issuer = value.GetString() }; break;
                case "sub": jwt = jwt with { Subject = value.GetString() }; break;
                case "aud": jwt = jwt with { Audience = value.Deserialize<TokenAudience>(options) }; break;
                case "exp": jwt = jwt with { ExpiresAt = Number(value) }; break;
                case "iat": jwt = jwt with { IssuedAt = Number(value) }; break;
                case "nbf": jwt = jwt with { NotBefore = Number(value) }; break;
                case "jti": jwt = jwt with { TokenId = value.GetString() }; break;
                case "client_id": access = access with { ClientId = value.GetString() }; break;
                case "scope": access = access with { Scope = value.GetString() }; break;
                case "nonce": authentication = authentication with { Nonce = value.GetString() }; break;
                case "auth_time": authentication = authentication with { AuthTime = Number(value) }; break;
                case "at_hash": authentication = authentication with { AccessTokenHash = value.GetString() }; break;
                case "email": profile = profile with { Email = value.GetString() }; break;
                case "name": profile = profile with { Name = value.GetString() }; break;
                case "locale": profile = profile with { Locale = value.GetString() }; break;
                case "token_use": simulator = simulator with { TokenUse = value.GetString() }; break;
                case "grant_type": simulator = simulator with { GrantType = value.GetString() }; break;
                case "country": simulator = simulator with { Country = value.GetString() }; break;
                case "language": simulator = simulator with { Language = value.GetString() }; break;
                default: custom[claim.Name] = value.Clone(); break;
            }
        }
        return new TokenPayload
        {
            Jwt = jwt, Access = access, Authentication = authentication, Profile = profile, Simulator = simulator,
            CustomClaims = custom, ExplicitNullClaims = nulls.ToFrozenSet(StringComparer.Ordinal)
        };
    }

    private static long? Number(JsonElement value) => value.ValueKind == JsonValueKind.Null ? null : value.GetInt64();

    public override void Write(Utf8JsonWriter writer, TokenPayload value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        WriteString("iss", value.Jwt.Issuer);
        WriteString("sub", value.Jwt.Subject);
        if (value.Jwt.Audience is not null)
        {
            writer.WritePropertyName("aud");
            JsonSerializer.Serialize(writer, value.Jwt.Audience, options);
        }
        else if (value.ExplicitNullClaims.Contains("aud")) writer.WriteNull("aud");
        WriteNumber("exp", value.Jwt.ExpiresAt);
        WriteNumber("iat", value.Jwt.IssuedAt);
        WriteNumber("nbf", value.Jwt.NotBefore);
        WriteString("jti", value.Jwt.TokenId);
        WriteString("client_id", value.Access.ClientId);
        WriteString("scope", value.Access.Scope);
        WriteString("nonce", value.Authentication.Nonce);
        WriteNumber("auth_time", value.Authentication.AuthTime);
        WriteString("at_hash", value.Authentication.AccessTokenHash);
        WriteString("email", value.Profile.Email);
        WriteString("name", value.Profile.Name);
        WriteString("locale", value.Profile.Locale);
        WriteString("token_use", value.Simulator.TokenUse);
        WriteString("grant_type", value.Simulator.GrantType);
        WriteString("country", value.Simulator.Country);
        WriteString("language", value.Simulator.Language);
        foreach (var claim in value.CustomClaims)
        {
            if (KnownClaims.Contains(claim.Key)) continue;
            writer.WritePropertyName(claim.Key);
            claim.Value.WriteTo(writer);
        }
        writer.WriteEndObject();

        void WriteString(string name, string? claim)
        {
            if (claim is not null) writer.WriteString(name, claim);
            else if (value.ExplicitNullClaims.Contains(name)) writer.WriteNull(name);
        }

        void WriteNumber(string name, long? claim)
        {
            if (claim.HasValue) writer.WriteNumber(name, claim.Value);
            else if (value.ExplicitNullClaims.Contains(name)) writer.WriteNull(name);
        }
    }
}
