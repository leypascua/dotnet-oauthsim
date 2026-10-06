using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.Extensions.Options;
using OAuthSim.Web.Models;

namespace OAuthSim.Web.Services;

// Scoped state shared by authentication, authorization and the action. No token claims
// are trusted until ValidateAccess has checked the signature and protocol fields.
public sealed class IntrospectionRequest(SettingsStore store, TokenService tokens, SecurityState security)
{
    public const string Policy = "Introspection";
    public const string Scheme = "IntrospectionBasic";
    private string? basicClientId;
    private string? basicSecret;
    public ProtocolException? Error { get; private set; }
    public Dictionary<string, object?> Response { get; private set; } = new() { ["active"] = false };

    public OAuthClient? Authenticate(HttpRequest request)
    {
        var headers = request.Headers.Authorization;
        if (headers.Count == 0) return null;
        try
        {
            if (headers.Count != 1 || !headers[0]!.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                throw new ProtocolException("invalid_client", "Unsupported client authentication.");
            try
            {
                var decoded = new UTF8Encoding(false, true).GetString(Convert.FromBase64String(headers[0]![6..]));
                var split = decoded.IndexOf(':');
                if (split < 0) throw new FormatException();
                basicClientId = System.Net.WebUtility.UrlDecode(decoded[..split]);
                basicSecret = System.Net.WebUtility.UrlDecode(decoded[(split + 1)..]);
            }
            catch (Exception ex) when (ex is FormatException or DecoderFallbackException)
            { throw new ProtocolException("invalid_client", "Malformed Basic authentication."); }
            lock (security.Gate) return BasicClient();
        }
        catch (ProtocolException ex) { Error = ex; return null; }
    }

    private OAuthClient BasicClient()
    {
        var client = store.Read().Clients.FirstOrDefault(c => c.Enabled && c.ClientId == basicClientId);
        if (client is null || client.IsPublic || string.IsNullOrEmpty(basicSecret)
            || !TokenService.SecretMatches(client.ClientSecret, basicSecret))
            throw new ProtocolException("invalid_client", "Client authentication failed.");
        return client;
    }

    public async Task<bool> Evaluate(HttpRequest request)
    {
        try
        {
            if (request.ContentType?.Split(';')[0].Trim().Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) != true)
                throw new ProtocolException("invalid_request", "Use application/x-www-form-urlencoded.");
            var form = await request.ReadFormAsync();
            foreach (var pair in form)
                if (pair.Value.Count != 1) throw new ProtocolException("invalid_request", $"Duplicate parameter: {pair.Key}.");
            if (form.ContainsKey("client_secret"))
                throw new ProtocolException("invalid_request", "Introspection accepts Basic authentication only; omit client_secret form fields.");
            if (Error is not null) return false;
            var token = form["token"].ToString();
            if (string.IsNullOrWhiteSpace(token)) throw new ProtocolException("invalid_request", "Provide a token.");
            lock (security.Gate)
            {
                // Recheck current client settings after asynchronous form parsing.
                var caller = basicClientId is null ? null : BasicClient();
                if (caller is not null && form["client_id"].ToString() is { Length: > 0 } id && id != caller.ClientId)
                    throw new ProtocolException("invalid_client", "Conflicting client IDs.");
                ValidatedAccessToken validated;
                // token_type_hint is advisory. Unidentifiable anonymous tokens only
                // authorize an inactive response, never disclosure of token claims.
                try { validated = tokens.ValidateAccess(token); }
                catch (ProtocolException ex) when (ex.Error == "invalid_token") { return true; }
                // The authenticated resource server need not be the client that acquired
                // the token, but must be an intended recipient of the validated token.
                if (caller is not null && validated.Jwt.Audience?.Contains(caller.ClientId) != true) return true;
                var owner = store.Read().Clients.FirstOrDefault(c => c.Enabled && c.ClientId == validated.Access.ClientId);
                if (owner is null) return true;
                if (caller is null && owner.RequireIntrospectionBasicAuthentication)
                    throw new ProtocolException("invalid_client", "Basic authentication is required for this client.");
                Response = validated.ToClaims().ToDictionary(c => c.Key, c => (object?)c.Value);
                Response["active"] = true;
                Response["token_type"] = "Bearer";
                return true;
            }
        }
        catch (ProtocolException ex) { Error = ex; return false; }
        catch (Exception ex) when (ex is InvalidDataException or BadHttpRequestException)
        { Error = new("invalid_request", "Malformed introspection form."); return false; }
    }
}

public sealed class IntrospectionBasicHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger, UrlEncoder encoder, IntrospectionRequest request)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // This scheme is specific to introspection, even if the framework selects
        // the only registered scheme as its implicit authentication default.
        if (Context.GetEndpoint()?.Metadata.GetOrderedMetadata<IAuthorizeData>().Any(a => a.Policy == IntrospectionRequest.Policy) != true)
            return Task.FromResult(AuthenticateResult.NoResult());
        var client = request.Authenticate(Request);
        if (request.Error is not null) return Task.FromResult(AuthenticateResult.Fail(request.Error));
        if (client is null) return Task.FromResult(AuthenticateResult.NoResult());
        var identity = new ClaimsIdentity([new Claim("client_id", client.ClientId)], Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(new(new ClaimsPrincipal(identity), Scheme.Name)));
    }
}

public sealed class IntrospectionRequirement : IAuthorizationRequirement;

public sealed class IntrospectionAuthorizationHandler(IntrospectionRequest request) : AuthorizationHandler<IntrospectionRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, IntrospectionRequirement requirement)
    {
        if (context.Resource is HttpContext http && await request.Evaluate(http.Request)) context.Succeed(requirement);
        else context.Fail();
    }
}

public sealed class IntrospectionAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler fallback = new();

    public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult result)
    {
        if (result.Succeeded || !policy.Requirements.OfType<IntrospectionRequirement>().Any())
        { await fallback.HandleAsync(next, context, policy, result); return; }
        var error = context.RequestServices.GetRequiredService<IntrospectionRequest>().Error
            ?? new ProtocolException("invalid_client", "Client authentication failed.");
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        if (error.Error == "invalid_client") context.Response.Headers.WWWAuthenticate = "Basic realm=\"OAuthSim\"";
        context.Response.StatusCode = error.Error == "invalid_client" ? 401 : 400;
        await context.Response.WriteAsJsonAsync(new { error = error.Error, error_description = error.Message });
    }
}
