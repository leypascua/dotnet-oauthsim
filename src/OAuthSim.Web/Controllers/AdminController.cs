using System.Net.Mail;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using OAuthSim.Web.Models;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed record AdminViewModel(SimulatorSettings Settings, string FilePath, string Issuer, string? Error = null, string? Message = null);
public sealed record UserFormModel(string Client, MockUser User, bool IsNew = false);

public sealed class AdminController(SettingsStore store, TokenService tokens, CountryLanguageCatalog catalog,
    LoginSessionService sessions, AuthorizationService authorization, SecurityState security) : Controller
{
    [HttpGet]
    public IActionResult Index() => View(Model());

    [HttpPost, ValidateAntiForgeryToken]
    public IActionResult InvalidateAll() => Mutate(() =>
    {
        lock (security.Gate)
        {
            tokens.InvalidateAll();
            sessions.InvalidateAll();
            authorization.InvalidateAll();
        }
    }, "All login sessions and tokens invalidated. Signing key rotated.");

    [HttpPost, ValidateAntiForgeryToken]
    public IActionResult SaveClient(string? id, string? clientId, string? clientSecret, string? name, bool isPublic,
        bool enabled, bool relaxRedirects, bool relaxScopes, string? redirectUris, string? scopes, bool makeDefault, bool generateSecret, string? claims)
    {
        return Mutate(() => store.Update(s =>
        {
            clientId = clientId?.Trim();
            if (string.IsNullOrWhiteSpace(clientId)) clientId = "oauthsim-" + SettingsStore.RandomValue();
            if (s.Clients.Any(c => c.ClientId == clientId && c.Id != id)) throw new ArgumentException("Client ID already exists.");
            var client = string.IsNullOrEmpty(id) ? new OAuthClient() : s.Clients.Single(c => c.Id == id);
            var redirects = (redirectUris ?? "").Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct().ToList();
            foreach (var redirect in redirects) AuthorizationService.ValidateRedirect(new OAuthClient(), redirect);
            var allowed = AuthorizationService.ParseScopes(scopes);
            AuthorizationService.ValidateScopes(new OAuthClient(), allowed);
            client.ClientId = clientId;
            client.Name = string.IsNullOrWhiteSpace(name) ? clientId : name.Trim();
            client.IsPublic = isPublic; client.Enabled = enabled;
            client.RelaxRedirects = relaxRedirects; client.RelaxScopes = relaxScopes;
            client.RedirectUris = redirects; client.Scopes = allowed.ToList();
            if (Request.Form.ContainsKey("claims")) client.ClaimsByScope = ParseClaims(claims);
            client.ClientSecret = generateSecret || string.IsNullOrWhiteSpace(clientSecret) ? SettingsStore.RandomValue() : clientSecret;
            if (string.IsNullOrEmpty(id)) s.Clients.Add(client);
            if (makeDefault || s.DefaultClientId is null) s.DefaultClientId = client.Id;
        }), "Client saved.");
    }

    [HttpPost, ValidateAntiForgeryToken]
    public IActionResult DeleteClient(string id) => Mutate(() => store.Update(s =>
    {
        if (s.Clients.Count == 1) throw new ArgumentException("Keep at least one client. You can disable it instead.");
        s.Clients.RemoveAll(c => c.Id == id);
        if (s.DefaultClientId == id) s.DefaultClientId = s.Clients[0].Id;
    }), "Client deleted.");

    [HttpPost, ValidateAntiForgeryToken]
    public IActionResult SaveUser(string client, string? id, string email, string? name, string country, string language, bool enabled, string? claims)
    {
        return Mutate(() => store.Update(s =>
        {
            var c = s.Clients.Single(c => c.Id == client);
            email = email?.Trim() ?? "";
            if (!MailAddress.TryCreate(email, out var address) || address.Address != email) throw new ArgumentException("Enter a valid email address.");
            if (c.Users.Any(u => u.Id != id && u.Email.Equals(email, StringComparison.OrdinalIgnoreCase))) throw new ArgumentException("This email already exists for the client.");
            if (!catalog.IsValid(country, language)) throw new ArgumentException("Select a valid country/language pair.");
            var user = string.IsNullOrEmpty(id) ? new MockUser() : c.Users.Single(u => u.Id == id);
            user.Email = email; user.Name = name?.Trim() ?? ""; user.Country = country; user.Language = language; user.Enabled = enabled;
            user.ClaimsByScope = ParseClaims(claims);
            if (string.IsNullOrEmpty(id)) c.Users.Add(user);
        }), "User saved.");
    }

    [HttpPost, ValidateAntiForgeryToken]
    public IActionResult DeleteUser(string client, string id) => Mutate(() => store.Update(s => s.Clients.Single(c => c.Id == client).Users.RemoveAll(u => u.Id == id)), "User deleted.");

    [HttpPost, ValidateAntiForgeryToken]
    public IActionResult SaveSettings(int codeLifetimeSeconds, int tokenLifetimeSeconds, int refreshLifetimeSeconds) => Mutate(() => store.Update(s =>
    {
        s.CodeLifetimeSeconds = codeLifetimeSeconds; s.TokenLifetimeSeconds = tokenLifetimeSeconds; s.RefreshLifetimeSeconds = refreshLifetimeSeconds;
    }), "Token lifetimes saved.");

    private AdminViewModel Model(string? error = null, string? message = null) => new(store.Read(), store.FilePath, tokens.Issuer, error, message);
    private static Dictionary<string, Dictionary<string, JsonElement>> ParseClaims(string? claims)
    {
        var result = string.IsNullOrWhiteSpace(claims) ? [] : JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, JsonElement>>>(claims)
            ?? throw new ArgumentException("Claims must be a JSON object keyed by scope.");
        if (result.Any(p => p.Value is null)) throw new ArgumentException("Invalid scope claims.");
        foreach (var scope in result.Keys) AuthorizationService.ValidateScopes(new OAuthClient(), [scope]);
        return result;
    }
    private IActionResult Mutate(Action operation, string message)
    {
        try
        {
            if (!ModelState.IsValid) throw new ArgumentException("One or more form values are missing or invalid.");
            operation();
            if (Request.Headers["HX-Request"] == "true") return PartialView("_Dashboard", Model(message: message));
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or JsonException or ProtocolException)
        {
            Response.StatusCode = 422;
            return Request.Headers["HX-Request"] == "true" ? PartialView("_Dashboard", Model(error: ex.Message)) : View("Index", Model(error: ex.Message));
        }
    }
}
