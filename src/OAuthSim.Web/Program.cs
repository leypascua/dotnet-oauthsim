using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.HttpOverrides;
using OAuthSim.Web.Cli;
using OAuthSim.Web.Services;

if (args.Contains("--help")) { Console.WriteLine(Options.Help); return 0; }
if (args.Contains("--version")) { Console.WriteLine("OAuthSim 0.4.0"); return 0; }

try
{
    var options = Options.Parse(args);
    using var store = new SettingsStore(options.SettingsDirectory);
    store.ApplyStartup(options);
    var port = store.Read().Port;
    var managedBindings = options.Hosted || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ASPNETCORE_PORT"))
        || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("APP_POOL_ID"));

    WebApplication BuildHost(int requestedPort)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = [], ContentRootPath = AppContext.BaseDirectory,
            ApplicationName = typeof(SettingsStore).Assembly.GetName().Name
        });
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        var settings = store.Read();
        managedBindings |= options.Port is null && settings.PublicBaseUrl is not null
            && (!string.IsNullOrEmpty(builder.Configuration["urls"]) || !string.IsNullOrEmpty(builder.Configuration["HTTP_PORTS"])
                || !string.IsNullOrEmpty(builder.Configuration["HTTPS_PORTS"]) || builder.Configuration.GetSection("Kestrel:Endpoints").GetChildren().Any());
        if (managedBindings && settings.PublicBaseUrl is null)
            throw new InvalidOperationException("Hosted deployments require --public-base-url or a saved publicBaseUrl.");
        if (!managedBindings) builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, requestedPort));
        builder.Services.Configure<ForwardedHeadersOptions>(forwarding => HostingConfiguration.ConfigureForwarding(forwarding, settings));
        builder.Services.AddSingleton(store);
        builder.Services.AddSingleton<CountryLanguageCatalog>();
        builder.Services.AddSingleton<TokenService>();
        builder.Services.AddSingleton<AuthorizationService>();
        builder.Services.AddSingleton<SecurityState>();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<LoginSessionService>();
        builder.Services.AddControllersWithViews();
        builder.Services.AddScoped<IntrospectionRequest>();
        builder.Services.AddAuthentication().AddScheme<AuthenticationSchemeOptions, IntrospectionBasicHandler>(IntrospectionRequest.Scheme, _ => { });
        builder.Services.AddAuthorization(a => a.AddPolicy(IntrospectionRequest.Policy, policy =>
        {
            policy.AddAuthenticationSchemes(IntrospectionRequest.Scheme);
            policy.AddRequirements(new IntrospectionRequirement());
        }));
        builder.Services.AddScoped<IAuthorizationHandler, IntrospectionAuthorizationHandler>();
        builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, IntrospectionAuthorizationResultHandler>();
        builder.Services.AddAntiforgery(a =>
        {
            a.Cookie.Name = "OAuthSim.Antiforgery";
            a.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        });
        var host = builder.Build();
        host.UseForwardedHeaders();
        host.Use(async (context, next) =>
        {
            if (!HostingConfiguration.ApplyPathBase(context, settings))
            { context.Response.StatusCode = 400; await context.Response.WriteAsync("Application path does not match the configured public base URL."); return; }
            await next();
        });
        host.UseExceptionHandler("/Home/Error");
        host.Use(async (context, next) =>
        {
            // The issuer is canonical and cannot be changed by a request's Host header.
            if (!HostingConfiguration.IsAllowedHost(context, settings))
            { context.Response.StatusCode = 400; await context.Response.WriteAsync("Use the public URL printed by OAuthSim."); return; }
            context.Response.Headers.CacheControl = "no-cache, no-store";
            context.Response.Headers.Pragma = "no-cache";
            await next();
        });
        host.UseRouting();
        host.UseMiddleware<ProtocolCorsMiddleware>();
        host.UseAuthentication();
        host.UseAuthorization();
        host.MapControllers();
        host.MapControllerRoute("default", "{controller=Admin}/{action=Index}/{id?}");
        return host;
    }

    var app = BuildHost(port);
    try { await app.StartAsync(); }
    catch (IOException) when (options.Port is null && !managedBindings)
    {
        await app.DisposeAsync();
        Console.WriteLine($"Port {port} is busy; selecting an available port.");
        app = BuildHost(0);
        await app.StartAsync();
    }
    await using (app)
    {
        if (!managedBindings)
        {
            var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            port = new Uri(address).Port;
        }
        store.Update(s => s.Port = port);
        var baseUrl = HostingConfiguration.BaseUrl(store.Read());
        Console.WriteLine($"OAuthSim 0.4.0\nAdmin:     {baseUrl}/\nDiscovery: {baseUrl}/.well-known/openid-configuration\nSettings:  {store.FilePath}");
        var clients = store.Read().Clients;
        if (clients.Count == 1)
        {
            Console.WriteLine($"Client ID: {clients[0].ClientId}");
            Console.WriteLine(clients[0].IsPublic ? "Public client: PKCE required" : $"Secret:    {clients[0].ClientSecret}");
        }
        if (!options.NoBrowser && !managedBindings)
        {
            try
            {
                if (OperatingSystem.IsWindows()) Process.Start(new ProcessStartInfo(baseUrl) { UseShellExecute = true });
                else Process.Start(OperatingSystem.IsMacOS() ? "open" : "xdg-open", [baseUrl]);
            }
            catch (Exception ex) { Console.WriteLine($"Could not open a browser: {ex.Message}\nOpen {baseUrl} manually."); }
        }
        await app.WaitForShutdownAsync();
    }
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"OAuthSim: {ex.Message}");
    return 1;
}
