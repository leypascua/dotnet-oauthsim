using Microsoft.AspNetCore.Mvc;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed partial class OAuthController
{
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
}
