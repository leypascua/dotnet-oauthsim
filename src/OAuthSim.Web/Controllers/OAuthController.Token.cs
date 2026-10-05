using Microsoft.AspNetCore.Mvc;
using OAuthSim.Web.Models;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed partial class OAuthController
{
    [HttpPost("/token"), HttpPost("/oauth/v2/token")]
    public async Task<IActionResult> Token()
    {
        try
        {
            var form = await ReadProtocolForm();
            lock (security.Gate)
            {
                var client = AuthenticateClient(form);
                var id = client.ClientId;
                TokenResponse result;
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
            return ProtocolError(ex);
        }
    }
}
