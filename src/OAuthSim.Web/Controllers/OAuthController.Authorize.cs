using Microsoft.AspNetCore.Mvc;
using OAuthSim.Web.Models;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed partial class OAuthController
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
}
