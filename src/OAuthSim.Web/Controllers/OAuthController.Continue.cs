using Microsoft.AspNetCore.Mvc;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed partial class OAuthController
{
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
}
