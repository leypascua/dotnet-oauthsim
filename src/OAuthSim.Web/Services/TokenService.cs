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
    private static readonly HashSet<string> Reserved = new(StringComparer.Ordinal)
    { "iss", "aud", "sub", "exp", "iat", "nbf", "jti", "nonce", "auth_time", "scope", "client_id", "token_use", "grant_type", "at_hash", "email", "name", "country", "language", "locale" };
    private static readonly HashSet<string> UserScopes = new(StringComparer.Ordinal) { "openid", "profile", "email", "offline_access" };

    public static bool IsUserScope(string scope) => UserScopes.Contains(scope);

    public Dictionary<string, object?> IssueClientCredentials(OAuthClient client, string[] scopes)
    {
        if (!client.Enabled || client.IsPublic) throw new ProtocolException("unauthorized_client", "Client credentials requires an enabled confidential client.");
        AuthorizationService.ValidateScopes(client, scopes);
        if (scopes.Any(IsUserScope)) throw new ProtocolException("invalid_scope", "User identity and offline_access scopes are not supported by client_credentials.");
        lock (gate)
        {
            var claims = new Dictionary<string, object?> { ["sub"] = client.ClientId };
            AddScopedClaims(claims, client.ClaimsByScope, scopes);
            return AccessResponse(client.ClientId, scopes, claims, "client_credentials");
        }
    }

    public TokenService(SettingsStore store)
    {
        this.store = store;
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(store.Read().SigningPrivateKey), out _);
    }

    public string Issuer => $"http://localhost:{store.Read().Port}";

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

    public object Jwks()
    {
        lock (gate)
        {
            var p = rsa.ExportParameters(false);
            return new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = store.Read().SigningKeyId, n = Base64Url(p.Modulus!), e = Base64Url(p.Exponent!) } } };
        }
    }

    public Dictionary<string, object?> Issue(Grant grant, string? family = null)
    {
        lock (gate)
        {
            var settings = store.Read();
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var claims = UserClaims(grant.Identity, grant.Scopes);
            var result = AccessResponse(grant.ClientId, grant.Scopes, claims, "authorization_code");
            var access = (string)result["access_token"]!;
            if (grant.Scopes.Contains("openid"))
            {
                var id = UserClaims(grant.Identity, grant.Scopes);
                id["iss"] = Issuer; id["aud"] = grant.ClientId; id["iat"] = now;
                id["exp"] = now + settings.TokenLifetimeSeconds;
                id["auth_time"] = grant.AuthTime.ToUnixTimeSeconds();
                id["at_hash"] = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(access))[..16]);
                if (grant.Nonce is not null) id["nonce"] = grant.Nonce;
                result["id_token"] = Sign(id, "JWT");
            }
            if (grant.Scopes.Contains("offline_access"))
            {
                PruneRefresh();
                var value = SettingsStore.RandomValue();
                var expiry = DateTimeOffset.UtcNow.AddSeconds(settings.RefreshLifetimeSeconds);
                refresh[Hash(value)] = new(grant, family ?? Guid.NewGuid().ToString("N"), false, expiry);
                result["refresh_token"] = value;
            }
            return result;
        }
    }

    public Dictionary<string, object?> Refresh(string token, string clientId, string[]? scopes)
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

    public Dictionary<string, JsonElement> ValidateAccess(string token)
    {
        lock (gate) return ValidateAccessCore(token);
    }

    private Dictionary<string, JsonElement> ValidateAccessCore(string token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) throw new FormatException();
            using var header = JsonDocument.Parse(Decode(parts[0]));
            if (header.RootElement.GetProperty("alg").GetString() != "RS256" || header.RootElement.GetProperty("typ").GetString() != "at+jwt"
                || header.RootElement.GetProperty("kid").GetString() != store.Read().SigningKeyId) throw new FormatException();
            lock (gate)
                if (!rsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Decode(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                    throw new FormatException();
            var claims = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Decode(parts[1]))!;
            if (claims["iss"].GetString() != Issuer || claims["token_use"].GetString() != "access"
                || claims["exp"].GetInt64() <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                || !store.Read().Clients.Any(c => c.Enabled && c.ClientId == claims["client_id"].GetString())
                || claims["aud"].GetString() != claims["client_id"].GetString()) throw new FormatException();
            return claims;
        }
        catch (Exception ex) when (ex is FormatException or JsonException or KeyNotFoundException or InvalidOperationException or CryptographicException)
        { throw new ProtocolException("invalid_token", "Bearer access token is invalid or expired."); }
    }

    public static Dictionary<string, object?> UserClaims(Identity identity, string[] scopes)
    {
        var result = new Dictionary<string, object?> { ["sub"] = identity.Subject };
        if (scopes.Contains("email")) result["email"] = identity.Email;
        if (scopes.Contains("profile"))
        {
            result["name"] = identity.Name;
            result["country"] = identity.Country;
            result["language"] = identity.Language;
            result["locale"] = identity.Language.Contains('-') ? identity.Language : identity.Language + "-" + identity.Country;
        }
        AddScopedClaims(result, identity.ClaimsByScope, scopes);
        return result;
    }

    private static void AddScopedClaims(Dictionary<string, object?> result,
        Dictionary<string, Dictionary<string, JsonElement>> claimsByScope, string[] scopes)
    {
        foreach (var scope in scopes)
            if (claimsByScope.TryGetValue(scope, out var claims))
                foreach (var claim in claims)
                    if (!Reserved.Contains(claim.Key)) result[claim.Key] = claim.Value;
    }

    // Call while holding gate: RSA signing is shared by user and application tokens.
    private Dictionary<string, object?> AccessResponse(string clientId, string[] scopes, Dictionary<string, object?> claims, string grantType)
    {
        var lifetime = store.Read().TokenLifetimeSeconds;
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        claims["iss"] = Issuer; claims["aud"] = clientId; claims["client_id"] = clientId;
        claims["iat"] = now; claims["exp"] = now + lifetime;
        claims["jti"] = Guid.NewGuid().ToString("N");
        claims["scope"] = string.Join(' ', scopes); claims["token_use"] = "access";
        claims["grant_type"] = grantType;
        return new()
        {
            ["access_token"] = Sign(claims, "at+jwt"), ["token_type"] = "Bearer",
            ["expires_in"] = lifetime, ["scope"] = string.Join(' ', scopes)
        };
    }

    public static bool SecretMatches(string expected, string supplied) => CryptographicOperations.FixedTimeEquals(
        SHA256.HashData(Encoding.UTF8.GetBytes(expected)), SHA256.HashData(Encoding.UTF8.GetBytes(supplied)));
    public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private string Sign(Dictionary<string, object?> claims, string type)
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
