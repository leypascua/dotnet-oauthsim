using Microsoft.AspNetCore.Mvc;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed class DiscoveryController(TokenService tokens) : Controller
{
    [HttpGet("/.well-known/openid-configuration")]
    public IActionResult Configuration() => Json(new
    {
        issuer = tokens.Issuer,
        authorization_endpoint = tokens.Issuer + "/oauth/v2/authorize",
        token_endpoint = tokens.Issuer + "/oauth/v2/token",
        userinfo_endpoint = tokens.Issuer + "/oauth/v2/userinfo",
        jwks_uri = tokens.Issuer + "/oauth/v2/jwks",
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

    [HttpGet("/oauth/v2/jwks")]
    public IActionResult Keys() => Json(tokens.Jwks());
}
