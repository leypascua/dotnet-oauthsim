using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed partial class OAuthController
{
    [HttpPost("/introspect"), HttpPost("/oauth/v2/introspect")]
    [Authorize(Policy = IntrospectionRequest.Policy)]
    public IActionResult Introspect([FromServices] IntrospectionRequest request)
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        return Json(request.Response);
    }
}
