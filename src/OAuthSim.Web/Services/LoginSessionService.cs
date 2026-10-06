using Microsoft.AspNetCore.Http;
using OAuthSim.Web.Models;

namespace OAuthSim.Web.Services;

// Serializes protocol completion with the administrator's global reset.
public sealed class SecurityState
{
    public object Gate { get; } = new();
}

public sealed record LoginSession(string ClientId, Identity Identity, DateTimeOffset AuthTime, DateTimeOffset ExpiresAt);

public sealed class LoginSessionService(SecurityState security, TimeProvider clock)
{
    private readonly Dictionary<string, LoginSession> sessions = [];
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);
    private static string CookieName(OAuthClient client) => "OAuthSim.Login." + client.Id;
    private static CookieOptions CookieOptions(HttpContext context) => new()
    {
        HttpOnly = true, SameSite = SameSiteMode.Lax, Secure = context.Request.IsHttps,
        Path = context.Request.PathBase.HasValue ? context.Request.PathBase.Value : "/", IsEssential = true, MaxAge = Lifetime
    };

    public LoginSession? Get(HttpContext context, OAuthClient client, bool renew = false)
    {
        lock (security.Gate)
        {
            if (!context.Request.Cookies.TryGetValue(CookieName(client), out var key)
                || !sessions.TryGetValue(key, out var session)) return null;
            var user = client.Users.FirstOrDefault(u => u.Id == session.Identity.Subject && u.Enabled);
            if (!client.Enabled || session.ClientId != client.ClientId || session.ExpiresAt <= clock.GetUtcNow()
                || (client.Users.Count > 0 && user is null)
                || (client.Users.Count == 0 && !session.Identity.Subject.StartsWith("adhoc-", StringComparison.Ordinal)))
            {
                Logout(context, client);
                return null;
            }
            // Apply current profile and scope claims for configured users.
            if (user is not null)
                session = session with { Identity = session.Identity with
                { Email = user.Email, Name = string.IsNullOrWhiteSpace(user.Name) ? user.Email : user.Name, ClaimsByScope = user.ClaimsByScope } };
            if (renew)
            {
                session = session with { ExpiresAt = clock.GetUtcNow().Add(Lifetime) };
                context.Response.Cookies.Append(CookieName(client), key, CookieOptions(context));
            }
            sessions[key] = session;
            return session;
        }
    }

    public void Create(HttpContext context, OAuthClient client, Identity identity, DateTimeOffset authTime)
    {
        lock (security.Gate)
        {
            Logout(context, client);
            foreach (var key in sessions.Where(p => p.Value.ExpiresAt <= clock.GetUtcNow()).Select(p => p.Key).ToArray()) sessions.Remove(key);
            var value = SettingsStore.RandomValue();
            sessions[value] = new(client.ClientId, identity, authTime, clock.GetUtcNow().Add(Lifetime));
            context.Response.Cookies.Append(CookieName(client), value, CookieOptions(context));
        }
    }

    public void Logout(HttpContext context, OAuthClient client)
    {
        lock (security.Gate)
        {
            if (context.Request.Cookies.TryGetValue(CookieName(client), out var key)) sessions.Remove(key);
            context.Response.Cookies.Delete(CookieName(client), CookieOptions(context));
        }
    }

    public void InvalidateAll() { lock (security.Gate) sessions.Clear(); }
}
