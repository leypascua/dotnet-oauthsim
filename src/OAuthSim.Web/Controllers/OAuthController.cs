using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using OAuthSim.Web.Models;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed class OAuthController(AuthorizationService authorization, TokenService tokens, SettingsStore store,
    CountryLanguageCatalog catalog, LoginSessionService sessions, SecurityState security) : Controller
{
    [HttpGet("/authorize"), HttpGet("/oauth/v2/authorize")]
    public IActionResult Authorize()
    {
        lock (security.Gate) return AuthorizeCore();
    }

    private IActionResult AuthorizeCore()
    {
        OAuthClient client;
        var redirect = Request.Query["redirect_uri"].ToString();
        try
        {
            client = authorization.Client(SingleQuery("client_id") ?? "");
            AuthorizationService.ValidateRedirect(client, SingleQuery("redirect_uri") ?? "");
        }
        catch (ProtocolException ex) { return LocalError(ex); }
        try
        {
            foreach (var pair in Request.Query) if (pair.Value.Count != 1) throw new ProtocolException("invalid_request", $"Duplicate parameter: {pair.Key}.");
            if (Request.Query["response_type"] != "code") throw new ProtocolException("unsupported_response_type", "Only response_type=code is supported.");
            var prompts = (SingleQuery("prompt") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (prompts.Except(new[] { "none", "login", "consent", "select_account" }).Any() || (prompts.Contains("none") && prompts.Length != 1))
                throw new ProtocolException("invalid_request", "Unsupported or conflicting prompt values.");
            var session = sessions.Get(HttpContext, client);
            var maxAge = SingleQuery("max_age");
            long? maximumAge = null;
            if (maxAge is not null)
            {
                if (!long.TryParse(maxAge, out var age) || age < 0) throw new ProtocolException("invalid_request", "max_age must be a nonnegative integer.");
                maximumAge = age;
                if (age == 0 || (session is not null && (DateTimeOffset.UtcNow - session.AuthTime).TotalSeconds > age)) session = null;
            }
            if (prompts.Any(p => p is "login" or "consent" or "select_account")) session = null;
            if (Request.Query["request"].Count > 0 || Request.Query["request_uri"].Count > 0)
                throw new ProtocolException("request_not_supported", "Request objects are not supported.");
            var request = authorization.Create(client.ClientId, redirect, AuthorizationService.ParseScopes(SingleQuery("scope")),
                SingleQuery("state"), SingleQuery("nonce"), SingleQuery("code_challenge"), SingleQuery("code_challenge_method"), SingleQuery("response_mode") ?? "query",
                session is not null, maximumAge);
            if (prompts.Contains("none"))
            {
                if (session is null) { authorization.Consume(request.Id); throw new ProtocolException("login_required", "A valid login session is required."); }
                sessions.Get(HttpContext, client, renew: true);
                return CompleteSession(request, session);
            }
            if (session is not null)
            {
                sessions.Get(HttpContext, client, renew: true);
                return View("Welcome", new WelcomeViewModel(request, DisplayName(session.Identity)));
            }
            return View("Login", new LoginViewModel(request, client));
        }
        catch (ProtocolException ex)
        {
            return Complete(redirect, Request.Query["response_mode"] == "form_post" ? "form_post" : "query",
                new() { ["error"] = ex.Error, ["error_description"] = ex.Message, ["state"] = Request.Query["state"].ToString() });
        }
    }

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

    [HttpPost("/oauth/v2/continue"), ValidateAntiForgeryToken]
    public IActionResult Continue(string transactionId)
    {
        lock (security.Gate)
        {
            try
            {
                var request = authorization.Get(transactionId);
                var client = authorization.Client(request.ClientId);
                AuthorizationService.ValidateRedirect(client, request.RedirectUri);
                AuthorizationService.ValidateScopes(client, request.Scopes);
                var session = request.AllowSessionReuse ? sessions.Get(HttpContext, client) : null;
                if (session is not null && request.MaxAge is { } age && (DateTimeOffset.UtcNow - session.AuthTime).TotalSeconds > age) session = null;
                if (session is null) return View("Login", new LoginViewModel(request, client, "Your login session expired. Sign in again."));
                sessions.Get(HttpContext, client, renew: true);
                return CompleteSession(request, session);
            }
            catch (ProtocolException ex) { return LocalError(ex); }
        }
    }

    [HttpPost("/oauth/v2/logout"), ValidateAntiForgeryToken]
    public IActionResult Logout(string transactionId)
    {
        lock (security.Gate)
        {
            try
            {
                var request = authorization.Get(transactionId);
                var client = authorization.Client(request.ClientId);
                sessions.Logout(HttpContext, client);
                return View("Login", new LoginViewModel(authorization.RequireLogin(request.Id), client));
            }
            catch (ProtocolException ex) { return LocalError(ex); }
        }
    }

    private IActionResult CompleteSession(AuthorizationRequest request, LoginSession session)
    {
        var code = authorization.IssueCode(request, session.Identity, request.Scopes, session.AuthTime);
        return Complete(request.RedirectUri, request.ResponseMode, new() { ["code"] = code, ["state"] = request.State });
    }

    private static string DisplayName(Identity identity) => identity.Name != identity.Email && !string.IsNullOrWhiteSpace(identity.Name)
        ? identity.Name : identity.Email.Split('@')[0];

    [HttpPost("/token"), HttpPost("/oauth/v2/token")]
    public async Task<IActionResult> Token()
    {
        try
        {
            if (Request.ContentType?.Split(';')[0].Trim().Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) != true)
                throw new ProtocolException("invalid_request", "Use application/x-www-form-urlencoded.");
            var form = await Request.ReadFormAsync();
            lock (security.Gate)
            {
            foreach (var pair in form) if (pair.Value.Count != 1) throw new ProtocolException("invalid_request", $"Duplicate parameter: {pair.Key}.");
            var id = form["client_id"].ToString();
            var secret = form["client_secret"].ToString();
            var basic = Request.Headers.Authorization.ToString();
            if (!string.IsNullOrEmpty(basic))
            {
                if (!basic.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) throw new ProtocolException("invalid_client", "Unsupported client authentication.");
                if (form.ContainsKey("client_secret")) throw new ProtocolException("invalid_request", "Use only one client authentication method.");
                try
                {
                    var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(basic[6..]));
                    var split = decoded.IndexOf(':');
                    if (split < 0) throw new FormatException();
                    var basicId = WebUtilityDecode(decoded[..split]);
                    if (id.Length > 0 && id != basicId) throw new ProtocolException("invalid_client", "Conflicting client IDs.");
                    id = basicId; secret = WebUtilityDecode(decoded[(split + 1)..]);
                }
                catch (FormatException) { throw new ProtocolException("invalid_client", "Malformed Basic authentication."); }
            }
            var client = authorization.Client(id);
            if ((!client.IsPublic && (secret.Length == 0 || !TokenService.SecretMatches(client.ClientSecret, secret)))
                || (client.IsPublic && (secret.Length > 0 || basic.Length > 0)))
                throw new ProtocolException("invalid_client", "Client authentication failed.");
            Dictionary<string, object?> result;
            switch (form["grant_type"].ToString())
            {
                case "authorization_code":
                    var grant = authorization.Exchange(form["code"].ToString(), id, form["redirect_uri"].ToString(), form["code_verifier"].FirstOrDefault());
                    if (client.IsPublic && grant.Challenge is null) throw new ProtocolException("invalid_grant", "Public clients require PKCE.");
                    AuthorizationService.ValidateScopes(client, grant.Scopes);
                    result = tokens.Issue(grant);
                    break;
                case "refresh_token":
                    var scopes = form.ContainsKey("scope") ? AuthorizationService.ParseScopes(form["scope"].ToString()) : null;
                    if (scopes is not null) AuthorizationService.ValidateScopes(client, scopes);
                    result = tokens.Refresh(form["refresh_token"].ToString(), id, scopes);
                    break;
                case "client_credentials":
                    result = tokens.IssueClientCredentials(client, AuthorizationService.ParseScopes(form["scope"].ToString()));
                    break;
                default: throw new ProtocolException("unsupported_grant_type", "Supported grants: authorization_code, refresh_token, client_credentials.");
            }
            Response.Headers.Pragma = "no-cache";
            return Json(result);
            }
        }
        catch (ProtocolException ex)
        {
            if (ex.Error == "invalid_client") Response.Headers.WWWAuthenticate = "Basic realm=\"OAuthSim\"";
            return StatusCode(ex.Error == "invalid_client" ? 401 : 400, new { error = ex.Error, error_description = ex.Message });
        }
    }

    [HttpGet("/userinfo"), HttpPost("/userinfo"), HttpGet("/oauth/v2/userinfo"), HttpPost("/oauth/v2/userinfo")]
    public IActionResult UserInfo()
    {
        try
        {
            var header = Request.Headers.Authorization.ToString();
            if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) throw new ProtocolException("invalid_token", "Provide a bearer access token.");
            var claims = tokens.ValidateAccess(header[7..]);
            if (claims.TryGetValue("grant_type", out var grantType) && grantType.GetString() == "client_credentials")
                throw new ProtocolException("insufficient_scope", "Userinfo requires an end-user access token, not an application token.");
            var excluded = new HashSet<string> { "iss", "aud", "exp", "iat", "jti", "scope", "client_id", "token_use", "grant_type" };
            return Json(claims.Where(c => !excluded.Contains(c.Key)).ToDictionary());
        }
        catch (ProtocolException ex)
        {
            Response.Headers.WWWAuthenticate = $"Bearer error=\"{ex.Error}\"";
            return StatusCode(ex.Error == "insufficient_scope" ? 403 : 401, new { error = ex.Error, error_description = ex.Message });
        }
    }

    private string? SingleQuery(string name)
    {
        var value = Request.Query[name];
        if (value.Count > 1) throw new ProtocolException("invalid_request", $"Duplicate parameter: {name}.");
        return value.Count == 0 ? null : value.ToString();
    }
    private static string WebUtilityDecode(string value) => System.Net.WebUtility.UrlDecode(value);
    private IActionResult LocalError(ProtocolException ex) { Response.StatusCode = 400; return View("ProtocolError", ex.Message); }
    private IActionResult Complete(string redirect, string mode, Dictionary<string, string?> parameters)
    {
        var values = parameters.Where(p => p.Value is not null).ToDictionary(p => p.Key, p => p.Value!);
        if (mode == "form_post") return View("FormPost", new FormPostModel(redirect, values));
        return Redirect(QueryHelpers.AddQueryString(redirect, values!));
    }
}

public sealed record FormPostModel(string RedirectUri, Dictionary<string, string> Parameters);
