using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using OAuthSim.Web.Models;
using OAuthSim.Web.Services;

namespace OAuthSim.Web.Controllers;

public sealed partial class OAuthController(AuthorizationService authorization, TokenService tokens, SettingsStore store,
    CountryLanguageCatalog catalog, LoginSessionService sessions, SecurityState security) : Controller
{
    private IActionResult CompleteSession(AuthorizationRequest request, LoginSession session)
    {
        var code = authorization.IssueCode(request, session.Identity, request.Scopes, session.AuthTime);
        return Complete(request.RedirectUri, request.ResponseMode, new() { ["code"] = code, ["state"] = request.State });
    }

    private static string DisplayName(Identity identity) => identity.Name != identity.Email && !string.IsNullOrWhiteSpace(identity.Name)
        ? identity.Name : identity.Email.Split('@')[0];

    private async Task<IFormCollection> ReadProtocolForm()
    {
        if (Request.ContentType?.Split(';')[0].Trim().Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) != true)
            throw new ProtocolException("invalid_request", "Use application/x-www-form-urlencoded.");
        var form = await Request.ReadFormAsync();
        foreach (var pair in form) if (pair.Value.Count != 1) throw new ProtocolException("invalid_request", $"Duplicate parameter: {pair.Key}.");
        return form;
    }

    private OAuthClient AuthenticateClient(IFormCollection form, bool requireConfidential = false)
    {
        var id = form["client_id"].ToString();
        var secret = form["client_secret"].ToString();
        var basic = Request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(basic))
        {
            if (!basic.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) throw new ProtocolException("invalid_client", "Unsupported client authentication.");
            if (form.ContainsKey("client_secret")) throw new ProtocolException("invalid_request", "Use only one client authentication method.");
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(basic[6..]));
                var split = decoded.IndexOf(':');
                if (split < 0) throw new FormatException();
                var basicId = WebUtilityDecode(decoded[..split]);
                if (id.Length > 0 && id != basicId) throw new ProtocolException("invalid_client", "Conflicting client IDs.");
                id = basicId; secret = WebUtilityDecode(decoded[(split + 1)..]);
            }
            catch (FormatException) { throw new ProtocolException("invalid_client", "Malformed Basic authentication."); }
        }
        var client = authorization.Client(id);
        if ((requireConfidential && client.IsPublic)
            || (!client.IsPublic && (secret.Length == 0 || !TokenService.SecretMatches(client.ClientSecret, secret)))
            || (client.IsPublic && (secret.Length > 0 || basic.Length > 0)))
            throw new ProtocolException("invalid_client", "Client authentication failed.");
        return client;
    }

    private IActionResult ProtocolError(ProtocolException ex)
    {
        if (ex.Error == "invalid_client") Response.Headers.WWWAuthenticate = "Basic realm=\"OAuthSim\"";
        return StatusCode(ex.Error == "invalid_client" ? 401 : 400, new { error = ex.Error, error_description = ex.Message });
    }

    private string? SingleQuery(string name)
    {
        var value = Request.Query[name];
        if (value.Count > 1) throw new ProtocolException("invalid_request", $"Duplicate parameter: {name}.");
        return value.Count == 0 ? null : value.ToString();
    }
    private static string WebUtilityDecode(string value) => System.Net.WebUtility.UrlDecode(value);
    private IActionResult LocalError(ProtocolException ex) { Response.StatusCode = 400; return View("ProtocolError", ex.Message); }
    private IActionResult Complete(string redirect, string mode, Dictionary<string, string?> parameters)
    {
        var values = parameters.Where(p => p.Value is not null).ToDictionary(p => p.Key, p => p.Value!);
        if (mode == "form_post") return View("FormPost", new FormPostModel(redirect, values));
        return Redirect(QueryHelpers.AddQueryString(redirect, values!));
    }
}

public sealed record FormPostModel(string RedirectUri, Dictionary<string, string> Parameters);
