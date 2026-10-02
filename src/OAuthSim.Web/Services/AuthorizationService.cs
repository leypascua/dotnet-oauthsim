using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using OAuthSim.Web.Models;

namespace OAuthSim.Web.Services;

public sealed record AuthorizationRequest(string Id, string ClientId, string RedirectUri, string[] Scopes,
    string? State, string? Nonce, string? Challenge, string ResponseMode, DateTimeOffset ExpiresAt,
    bool AllowSessionReuse = true, long? MaxAge = null);
public sealed record Identity(string Subject, string Email, string Name, string Country, string Language,
    Dictionary<string, Dictionary<string, System.Text.Json.JsonElement>> ClaimsByScope);
public sealed record Grant(string ClientId, string RedirectUri, string[] Scopes, Identity Identity,
    string? Nonce, string? Challenge, DateTimeOffset AuthTime, DateTimeOffset ExpiresAt);
public sealed record LoginViewModel(AuthorizationRequest Request, OAuthClient Client, string? Error = null);
public sealed record WelcomeViewModel(AuthorizationRequest Request, string DisplayName);

public sealed class ProtocolException(string error, string description) : Exception(description)
{
    public string Error { get; } = error;
}

public sealed class AuthorizationService(SettingsStore store)
{
    private readonly ConcurrentDictionary<string, AuthorizationRequest> requests = new();
    private readonly ConcurrentDictionary<string, Grant> codes = new();

    public OAuthClient Client(string id) => store.Read().Clients.FirstOrDefault(c => c.Enabled && c.ClientId == id)
        ?? throw new ProtocolException("invalid_client", "Unknown or disabled client.");

    public static string[] ParseScopes(string? scopes) => (scopes ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToArray();

    public static void ValidateRedirect(OAuthClient client, string uri)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed) || parsed.Scheme is not ("http" or "https")
            || !string.IsNullOrEmpty(parsed.Fragment) || !string.IsNullOrEmpty(parsed.UserInfo))
            throw new ProtocolException("invalid_request", "redirect_uri must be an absolute HTTP(S) URL without a fragment or credentials.");
        if (!client.RelaxRedirects && client.RedirectUris.Count > 0 && !client.RedirectUris.Contains(uri, StringComparer.Ordinal))
            throw new ProtocolException("invalid_request", "redirect_uri is not registered for this client.");
    }

    public static void ValidateScopes(OAuthClient client, string[] scopes)
    {
        if (scopes.Any(s => s.Any(ch => ch < 0x21 || ch > 0x7e || ch is '"' or '\\')))
            throw new ProtocolException("invalid_scope", "Scopes must contain printable OAuth scope characters.");
        if (!client.RelaxScopes && client.Scopes.Count > 0 && scopes.Except(client.Scopes, StringComparer.Ordinal).Any())
            throw new ProtocolException("invalid_scope", "One or more scopes are not allowed for this client.");
    }

    public AuthorizationRequest Create(string clientId, string redirect, string[] scopes, string? state,
        string? nonce, string? challenge, string? challengeMethod, string mode, bool allowSessionReuse = true, long? maxAge = null)
    {
        Prune();
        var client = Client(clientId);
        ValidateRedirect(client, redirect);
        ValidateScopes(client, scopes);
        if (mode is not ("query" or "form_post")) throw new ProtocolException("invalid_request", "Supported response modes: query, form_post.");
        if (challenge is not null && (challengeMethod != "S256" || challenge.Length != 43 || !challenge.All(IsUnreserved)))
            throw new ProtocolException("invalid_request", "PKCE requires a base64url S256 challenge.");
        if (challenge is null && (client.IsPublic || challengeMethod is not null))
            throw new ProtocolException("invalid_request", "This request requires an S256 PKCE challenge.");
        var request = new AuthorizationRequest(SettingsStore.RandomValue(), clientId, redirect, scopes, state, nonce,
            challenge, mode, DateTimeOffset.UtcNow.AddMinutes(10), allowSessionReuse, maxAge);
        requests[request.Id] = request;
        return request;
    }

    public AuthorizationRequest Get(string id) => requests.TryGetValue(id, out var value) && value.ExpiresAt > DateTimeOffset.UtcNow
        ? value : throw new ProtocolException("invalid_request", "Login request has expired. Start authorization again.");

    public void Consume(string id)
    {
        if (!requests.TryRemove(id, out var value) || value.ExpiresAt <= DateTimeOffset.UtcNow)
            throw new ProtocolException("invalid_request", "Login request has expired or was already used.");
    }

    public string IssueCode(AuthorizationRequest request, Identity identity, string[] scopes, DateTimeOffset? authTime = null)
    {
        Consume(request.Id);
        var code = SettingsStore.RandomValue();
        codes[code] = new(request.ClientId, request.RedirectUri, scopes, identity, request.Nonce, request.Challenge,
            authTime ?? DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddSeconds(store.Read().CodeLifetimeSeconds));
        return code;
    }

    public Grant Exchange(string code, string clientId, string redirect, string? verifier)
    {
        if (!codes.TryRemove(code, out var grant) || grant.ExpiresAt <= DateTimeOffset.UtcNow || grant.ClientId != clientId || grant.RedirectUri != redirect)
            throw new ProtocolException("invalid_grant", "Authorization code is invalid, expired, or does not match the client/redirect URI.");
        if (grant.Challenge is not null)
        {
            if (verifier is null || verifier.Length is < 43 or > 128 || !verifier.All(IsUnreserved)
                || TokenService.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))) != grant.Challenge)
                throw new ProtocolException("invalid_grant", "PKCE verifier does not match.");
        }
        return grant;
    }

    private static bool IsUnreserved(char ch) => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '.' or '_' or '~';
    public void InvalidateAll() { requests.Clear(); codes.Clear(); }
    public AuthorizationRequest RequireLogin(string id)
    {
        var request = Get(id) with { AllowSessionReuse = false };
        requests[id] = request;
        return request;
    }
    private void Prune()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in requests.Where(p => p.Value.ExpiresAt <= now)) requests.TryRemove(pair.Key, out _);
        foreach (var pair in codes.Where(p => p.Value.ExpiresAt <= now)) codes.TryRemove(pair.Key, out _);
    }
}
