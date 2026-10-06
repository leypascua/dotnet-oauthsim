using System.Net;
using Microsoft.AspNetCore.HttpOverrides;
using OAuthSim.Web.Models;

namespace OAuthSim.Web.Services;

public static class HostingConfiguration
{
    public static string BaseUrl(SimulatorSettings settings) => settings.PublicBaseUrl ?? $"http://localhost:{settings.Port}";

    public static void ConfigureForwarding(ForwardedHeadersOptions options, SimulatorSettings settings)
    {
        options.ForwardedHeaders = settings.PublicBaseUrl is null ? ForwardedHeaders.None
            : ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
        options.ForwardLimit = 1;
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        var proxies = settings.TrustedProxies.Count == 0 ? ["127.0.0.1", "::1"] : settings.TrustedProxies;
        foreach (var proxy in proxies)
        {
            if (IPAddress.TryParse(proxy, out var address)) options.KnownProxies.Add(address);
            else options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(proxy));
        }
        options.AllowedHosts.Clear();
        if (settings.PublicBaseUrl is not null) options.AllowedHosts.Add(new Uri(settings.PublicBaseUrl).Host);
    }

    public static bool IsAllowedHost(HttpContext context, SimulatorSettings settings)
    {
        var host = context.Request.Host;
        var port = host.Port ?? (context.Request.IsHttps ? 443 : 80);
        if (settings.PublicBaseUrl is not null)
        {
            var publicUrl = new Uri(settings.PublicBaseUrl);
            if (string.Equals(host.Host, publicUrl.Host, StringComparison.OrdinalIgnoreCase) && port == publicUrl.Port) return true;
        }
        // Keep local backend access available for startup probes and local administration.
        return host.Host is "localhost" or "127.0.0.1" or "[::1]" && port == context.Connection.LocalPort;
    }

    public static bool ApplyPathBase(HttpContext context, SimulatorSettings settings)
    {
        if (settings.PublicBaseUrl is null) return true;
        var prefix = PathString.FromUriComponent(new Uri(settings.PublicBaseUrl).AbsolutePath.TrimEnd('/'));
        if (context.Request.PathBase == prefix) return true;
        if (context.Request.PathBase.HasValue) return false;
        if (!prefix.HasValue) return true;
        if (context.Request.Path.StartsWithSegments(prefix, out var remaining)) context.Request.Path = remaining;
        // IIS may already set PathBase; proxies may either preserve or strip the prefix.
        context.Request.PathBase = prefix;
        return true;
    }
}
