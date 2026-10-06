using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OAuthSim.Web.Models;

namespace OAuthSim.Web.Services;

public sealed class TokenService : IDisposable
{
    private readonly SettingsStore store;
    private readonly RSA rsa = RSA.Create();
    private readonly object gate = new();
    private readonly Dictionary<string, RefreshGrant> refresh = [];
    private sealed record RefreshGrant(Grant Grant, string Family, bool Used, DateTimeOffset ExpiresAt);
    private static readonly HashSet<string> UserScopes = new(StringComparer.Ordinal) { "openid", "profile", "email", "offline_access" };

    public static bool IsUserScope(string scope) => UserScopes.Contains(scope);

    public TokenResponse IssueClientCredentials(OAuthClient client, string[] scopes)
    {
        lock (gate)
        {
            var settings = store.Read();
            client = settings.Clients.FirstOrDefault(c => c.ClientId == client.ClientId)
                ?? throw new ProtocolException("unauthorized_client", "Unknown client.");
            if (!client.Enabled || client.IsPublic) throw new ProtocolException("unauthorized_client", "Client credentials requires an enabled confidential client.");
            AuthorizationService.ValidateScopes(client, scopes);
            if (scopes.Any(IsUserScope)) throw new ProtocolException("invalid_scope", "User identity and offline_access scopes are not supported by client_credentials.");
            var claims = new TokenPayload
            {
                Jwt = new JwtClaims { Subject = client.ClientId },
                CustomClaims = ScopedCustomClaims(client.ClaimsByScope, scopes)
            };
            return AccessResponse(client, settings, scopes, claims, "client_credentials");
        }
    }

    public TokenService(SettingsStore store)
    {
        this.store = store;
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(store.Read().SigningPrivateKey), out _);
    }

    public string BaseUrl => HostingConfiguration.BaseUrl(store.Read());
    public string Issuer => BaseUrl;

    public static string ResolveIssuer(OAuthClient client, string defaultIssuer) =>
        string.IsNullOrWhiteSpace(client.Issuer) ? defaultIssuer : client.Issuer.Trim();
    public static TokenAudience ResolveAccessTokenAudience(OAuthClient client) =>
        client.AccessTokenAudience?.Normalize() ?? new([client.ClientId]);

    public void InvalidateAll()
    {
        lock (gate)
        {
            using var replacement = RSA.Create(2048);
            var privateKey = replacement.ExportPkcs8PrivateKey();
            store.Update(s =>
            {
                s.SigningPrivateKey = Convert.ToBase64String(privateKey);
                s.SigningKeyId = Guid.NewGuid().ToString("N");
            });
            rsa.ImportPkcs8PrivateKey(privateKey, out _);
            refresh.Clear();
        }
    }

    public JsonWebKeySet Jwks()
    {
        lock (gate)
        {
            var p = rsa.ExportParameters(false);
            return new([new RsaJsonWebKey
            {
                KeyId = store.Read().SigningKeyId, Modulus = Base64Url(p.Modulus!), Exponent = Base64Url(p.Exponent!)
            }]);
        }
    }

    public TokenResponse Issue(Grant grant, string? family = null)
    {
        lock (gate)
        {
            var settings = store.Read();
            var client = settings.Clients.Single(c => c.Enabled && c.ClientId == grant.ClientId);
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var claims = UserClaims(grant.Identity, grant.Scopes);
            var result = AccessResponse(client, settings, grant.Scopes, claims, "authorization_code");
            if (grant.Scopes.Contains("openid"))
            {
                var id = claims with
                {
                    Jwt = claims.Jwt with
                    {
                        Issuer = ResolveIssuer(client, HostingConfiguration.BaseUrl(settings)), Audience = grant.ClientId, IssuedAt = now,
                        ExpiresAt = now + settings.TokenLifetimeSeconds
                    },
                    Authentication = new OidcAuthenticationClaims
                    {
                        AuthTime = grant.AuthTime.ToUnixTimeSeconds(), Nonce = grant.Nonce,
                        AccessTokenHash = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(result.AccessToken))[..16])
                    }
                };
                result = result with { IdToken = Sign(id, "JWT") };
            }
            if (grant.Scopes.Contains("offline_access"))
            {
                PruneRefresh();
                var value = SettingsStore.RandomValue();
                var expiry = DateTimeOffset.UtcNow.AddSeconds(settings.RefreshLifetimeSeconds);
                refresh[Hash(value)] = new(grant, family ?? Guid.NewGuid().ToString("N"), false, expiry);
                result = result with { RefreshToken = value };
            }
            return result;
        }
    }

    public TokenResponse Refresh(string token, string clientId, string[]? scopes)
    {
        lock (gate)
        {
            if (!refresh.TryGetValue(Hash(token), out var value) || value.ExpiresAt <= DateTimeOffset.UtcNow || value.Grant.ClientId != clientId)
                throw new ProtocolException("invalid_grant", "Refresh token is invalid or expired.");
            var client = store.Read().Clients.Single(c => c.Enabled && c.ClientId == clientId);
            AuthorizationService.ValidateScopes(client, scopes ?? value.Grant.Scopes);
            if (value.Used)
            {
                foreach (var key in refresh.Where(p => p.Value.Family == value.Family).Select(p => p.Key).ToArray()) refresh.Remove(key);
                throw new ProtocolException("invalid_grant", "Refresh token reuse detected; the token family has been invalidated.");
            }
            if (scopes is not null && scopes.Except(value.Grant.Scopes, StringComparer.Ordinal).Any())
                throw new ProtocolException("invalid_scope", "Refresh cannot expand the granted scopes.");
            refresh[Hash(token)] = value with { Used = true };
            return Issue(value.Grant with { Scopes = scopes ?? value.Grant.Scopes, Nonce = null }, value.Family);
        }
    }

    public ValidatedAccessToken ValidateAccess(string token)
    {
        lock (gate) return ValidateAccessCore(token);
    }

    private ValidatedAccessToken ValidateAccessCore(string token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) throw new FormatException();
            var settings = store.Read();
            using var header = JsonDocument.Parse(Decode(parts[0]));
            if (header.RootElement.GetProperty("alg").GetString() != "RS256" || header.RootElement.GetProperty("typ").GetString() != "at+jwt"
                || header.RootElement.GetProperty("kid").GetString() != settings.SigningKeyId) throw new FormatException();
            lock (gate)
                if (!rsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Decode(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                    throw new FormatException();
            var claims = JsonSerializer.Deserialize<TokenPayload>(Decode(parts[1])) ?? throw new FormatException();
            // Resolve identity expectations only from the signature-verified client_id,
            // never from a request parameter or the token's audience.
            var client = settings.Clients.FirstOrDefault(c => c.Enabled && c.ClientId == claims.Access.ClientId);
            if (client is null || claims.Jwt.Issuer != ResolveIssuer(client, HostingConfiguration.BaseUrl(settings)) || claims.Simulator.TokenUse != "access"
                || claims.Jwt.ExpiresAt is not long expiresAt || expiresAt <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                || claims.Access.ClientId is null
                || claims.Jwt.Audience is not { IsValid: true }
                || claims.Jwt.Audience != ResolveAccessTokenAudience(client)) throw new FormatException();
            return new ValidatedAccessToken(claims);
        }
        catch (Exception ex) when (ex is FormatException or JsonException or KeyNotFoundException or InvalidOperationException or CryptographicException)
        { throw new ProtocolException("invalid_token", "Bearer access token is invalid or expired."); }
    }

    public static TokenPayload UserClaims(Identity identity, string[] scopes)
    {
        var profile = scopes.Contains("profile");
        return new TokenPayload
        {
            Jwt = new JwtClaims { Subject = identity.Subject },
            Profile = new OidcProfileClaims
            {
                Email = scopes.Contains("email") ? identity.Email : null,
                Name = profile ? identity.Name : null,
                Locale = profile ? (identity.Language.Contains('-') ? identity.Language : identity.Language + "-" + identity.Country) : null
            },
            Simulator = new SimulatorClaims
            {
                Country = profile ? identity.Country : null, Language = profile ? identity.Language : null
            },
            CustomClaims = ScopedCustomClaims(identity.ClaimsByScope, scopes)
        };
    }

    private static Dictionary<string, JsonElement> ScopedCustomClaims(
        Dictionary<string, Dictionary<string, JsonElement>> claimsByScope, string[] scopes)
    {
        var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var scope in scopes)
            if (claimsByScope.TryGetValue(scope, out var claims))
                foreach (var claim in claims)
                    if (!TokenPayloadJsonConverter.KnownClaims.Contains(claim.Key)) result[claim.Key] = claim.Value;
        return result;
    }

    // Call while holding gate: RSA signing is shared by user and application tokens.
    private TokenResponse AccessResponse(OAuthClient client, SimulatorSettings settings, string[] scopes, TokenPayload claims, string grantType)
    {
        var lifetime = settings.TokenLifetimeSeconds;
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var scope = string.Join(' ', scopes);
        claims = claims with
        {
            Jwt = claims.Jwt with
            {
                Issuer = ResolveIssuer(client, HostingConfiguration.BaseUrl(settings)), Audience = ResolveAccessTokenAudience(client), IssuedAt = now, ExpiresAt = now + lifetime,
                TokenId = Guid.NewGuid().ToString("N")
            },
            Access = new AccessTokenClaims { ClientId = client.ClientId, Scope = scope },
            Simulator = claims.Simulator with { TokenUse = "access", GrantType = grantType }
        };
        return new()
        {
            AccessToken = Sign(claims, "at+jwt"),
            ExpiresIn = lifetime, Scope = scope
        };
    }

    public static bool SecretMatches(string expected, string supplied) => CryptographicOperations.FixedTimeEquals(
        SHA256.HashData(Encoding.UTF8.GetBytes(expected)), SHA256.HashData(Encoding.UTF8.GetBytes(supplied)));
    public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private string Sign(TokenPayload claims, string type)
    {
        var header = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", typ = type, kid = store.Read().SigningKeyId }));
        var payload = Base64Url(JsonSerializer.SerializeToUtf8Bytes(claims));
        var input = header + "." + payload;
        return input + "." + Base64Url(rsa.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }
    private void PruneRefresh()
    {
        foreach (var key in refresh.Where(p => p.Value.ExpiresAt <= DateTimeOffset.UtcNow).Select(p => p.Key).ToArray()) refresh.Remove(key);
    }
    public void Dispose() => rsa.Dispose();
}
