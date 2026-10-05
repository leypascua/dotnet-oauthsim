using Microsoft.AspNetCore.Mvc;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed class DiscoveryController(TokenService tokens, SettingsStore store) : Controller
{
    [HttpGet("/.well-known/openid-configuration")]
    public IActionResult Configuration([FromQuery(Name = "client_id")] string? clientId)
    {
        var defaultIssuer = tokens.Issuer;
        var issuer = defaultIssuer;
        if (Request.Query.ContainsKey("client_id"))
        {
            if (Request.Query["client_id"].Count != 1)
                return BadRequest(new { error = "invalid_request", error_description = "Provide a single client_id." });
            var client = store.Read().Clients.FirstOrDefault(c => c.Enabled && c.ClientId == clientId);
            if (client is null)
                return BadRequest(new { error = "invalid_client", error_description = "Unknown or disabled client." });
            issuer = TokenService.ResolveIssuer(client, defaultIssuer);
        }
        Response.Headers.CacheControl = "no-store";
        return Json(new
        {
            issuer,
            authorization_endpoint = defaultIssuer + "/oauth/v2/authorize",
            token_endpoint = defaultIssuer + "/oauth/v2/token",
            introspection_endpoint = defaultIssuer + "/oauth/v2/introspect",
            introspection_endpoint_auth_methods_supported = new[] { "client_secret_basic" },
            userinfo_endpoint = defaultIssuer + "/oauth/v2/userinfo",
            jwks_uri = defaultIssuer + "/oauth/v2/jwks",
            response_types_supported = new[] { "code" },
            response_modes_supported = new[] { "query", "form_post" },
            grant_types_supported = new[] { "authorization_code", "refresh_token", "client_credentials" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post", "none" },
            code_challenge_methods_supported = new[] { "S256" },
            scopes_supported = new[] { "openid", "profile", "email", "offline_access" },
            claims_supported = new[] { "sub", "iss", "aud", "iat", "exp", "nonce", "auth_time", "name", "email", "country", "language", "locale" }
        });
    }

    [HttpGet("/oauth/v2/jwks")]
    public IActionResult Keys() => Json(tokens.Jwks());
}
