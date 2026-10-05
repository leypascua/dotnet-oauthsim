using Microsoft.AspNetCore.Mvc;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed partial class OAuthController
{
    [HttpGet("/userinfo"), HttpPost("/userinfo"), HttpGet("/oauth/v2/userinfo"), HttpPost("/oauth/v2/userinfo")]
    public IActionResult UserInfo()
    {
        try
        {
            var header = Request.Headers.Authorization.ToString();
            if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) throw new ProtocolException("invalid_token", "Provide a bearer access token.");
            var token = tokens.ValidateAccess(header[7..]);
            if (token.Simulator.GrantType == "client_credentials")
                throw new ProtocolException("insufficient_scope", "Userinfo requires an end-user access token, not an application token.");
            return Json(token.ToUserInfo());
        }
        catch (ProtocolException ex)
        {
            Response.Headers.WWWAuthenticate = $"Bearer error=\"{ex.Error}\"";
            return StatusCode(ex.Error == "insufficient_scope" ? 403 : 401, new { error = ex.Error, error_description = ex.Message });
        }
    }
}
