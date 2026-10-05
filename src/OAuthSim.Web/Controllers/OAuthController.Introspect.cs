using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed partial class OAuthController
{
    [HttpPost("/introspect"), HttpPost("/oauth/v2/introspect")]
    public async Task<IActionResult> Introspect()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        try
        {
            var form = await ReadProtocolForm();
            lock (security.Gate)
            {
                var client = AuthenticateClient(form, requireConfidential: true);
                var token = form["token"].ToString();
                if (string.IsNullOrWhiteSpace(token)) throw new ProtocolException("invalid_request", "Provide a token.");
                Dictionary<string, JsonElement> claims;
                // token_type_hint is advisory; validation determines the supported token type.
                try { claims = tokens.ValidateAccess(token); }
                catch (ProtocolException ex) when (ex.Error == "invalid_token") { return Json(new { active = false }); }
                if (claims["client_id"].GetString() != client.ClientId) return Json(new { active = false });
                var result = claims.ToDictionary(c => c.Key, c => (object?)c.Value);
                result["active"] = true;
                result["token_type"] = "Bearer";
                return Json(result);
            }
        }
        catch (ProtocolException ex) { return ProtocolError(ex); }
    }
}
