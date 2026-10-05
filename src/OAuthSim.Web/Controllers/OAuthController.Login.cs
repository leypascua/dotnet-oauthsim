using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using OAuthSim.Web.Models;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed partial class OAuthController
{
    [HttpPost("/authorize"), HttpPost("/oauth/v2/authorize"), ValidateAntiForgeryToken]
    public IActionResult Login(string transactionId, string? userId, string? email, string country, string language, string? scopes, string? decision)
    {
        lock (security.Gate) return LoginCore(transactionId, userId, email, country, language, scopes, decision);
    }

    private IActionResult LoginCore(string transactionId, string? userId, string? email, string country, string language, string? scopes, string? decision)
    {
        AuthorizationRequest request;
        OAuthClient client;
        try
        {
            request = authorization.Get(transactionId);
            client = authorization.Client(request.ClientId);
            AuthorizationService.ValidateRedirect(client, request.RedirectUri);
        }
        catch (ProtocolException ex) { return LocalError(ex); }
        try
        {
            if (!ModelState.IsValid) throw new ProtocolException("invalid_request", "One or more login values are missing or invalid.");
            if (decision == "deny")
            {
                authorization.Consume(transactionId);
                return Complete(request.RedirectUri, request.ResponseMode, new() { ["error"] = "access_denied", ["state"] = request.State });
            }
            var granted = AuthorizationService.ParseScopes(scopes);
            AuthorizationService.ValidateScopes(client, granted);
            // The protocol mode cannot be enabled by editing scope text on the login form.
            if (granted.Contains("openid") && !request.Scopes.Contains("openid"))
                throw new ProtocolException("invalid_scope", "openid must be requested by the application.");
            var user = client.Users.FirstOrDefault(u => u.Id == userId && u.Enabled);
            if (client.Users.Count > 0 && user is null) throw new ProtocolException("invalid_request", "Select an enabled user.");
            email = user?.Email ?? email?.Trim();
            if (email is null || !MailAddress.TryCreate(email, out var address) || address.Address != email)
                throw new ProtocolException("invalid_request", "Enter a valid email address.");
            if (!catalog.IsValid(country, language)) throw new ProtocolException("invalid_request", "Select a valid country and language.");
            var subject = user?.Id ?? "adhoc-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(client.Id + ":" + email.ToLowerInvariant()))).ToLowerInvariant();
            var identity = new Identity(subject, email, user?.Name is { Length: > 0 } name ? name : email, country, language, user?.ClaimsByScope ?? []);
            store.Update(s => s.Clients.Single(c => c.Id == client.Id).LastLogin = new LoginPreferences
            { UserId = user?.Id, Email = email, Country = country, Language = language });
            var authTime = DateTimeOffset.UtcNow;
            var code = authorization.IssueCode(request, identity, granted, authTime);
            sessions.Create(HttpContext, client, identity, authTime);
            return Complete(request.RedirectUri, request.ResponseMode, new() { ["code"] = code, ["state"] = request.State });
        }
        catch (ProtocolException ex) { Response.StatusCode = 422; return View("Login", new LoginViewModel(request, client, ex.Message)); }
    }
}
