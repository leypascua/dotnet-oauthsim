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
}
