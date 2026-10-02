namespace OAuthSim.Web.Services;

public sealed class ProtocolCorsMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, SettingsStore store)
    {
        var path = context.Request.Path.Value ?? "";
        if (path is "/token" or "/userinfo" or "/oauth/v2/token" or "/oauth/v2/userinfo")
        {
            var origin = context.Request.Headers.Origin.ToString();
            if (!string.IsNullOrEmpty(origin))
            {
                var clients = store.Read().Clients.Where(c => c.Enabled);
                var allowed = Uri.TryCreate(origin, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https"
                    && clients.Any(c => c.RedirectUris.Any(r => Uri.TryCreate(r, UriKind.Absolute, out var redirect) && redirect.GetLeftPart(UriPartial.Authority) == origin)
                        || ((c.RedirectUris.Count == 0 || c.RelaxRedirects) && uri.Host is "localhost" or "127.0.0.1" or "[::1]"));
                if (allowed)
                {
                    context.Response.Headers.AccessControlAllowOrigin = origin;
                    context.Response.Headers.Vary = "Origin";
                    context.Response.Headers.AccessControlAllowMethods = "GET, POST, OPTIONS";
                    context.Response.Headers.AccessControlAllowHeaders = "Authorization, Content-Type";
                }
                if (context.Request.Method == "OPTIONS") { context.Response.StatusCode = allowed ? 204 : 403; return; }
            }
        }
        await next(context);
    }
}
