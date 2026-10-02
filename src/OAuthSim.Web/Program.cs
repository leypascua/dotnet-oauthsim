using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
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

    WebApplication BuildHost(int requestedPort)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = [], ContentRootPath = AppContext.BaseDirectory,
            ApplicationName = typeof(SettingsStore).Assembly.GetName().Name
        });
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, requestedPort));
        builder.Services.AddSingleton(store);
        builder.Services.AddSingleton<CountryLanguageCatalog>();
        builder.Services.AddSingleton<TokenService>();
        builder.Services.AddSingleton<AuthorizationService>();
        builder.Services.AddSingleton<SecurityState>();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<LoginSessionService>();
        builder.Services.AddControllersWithViews();
        builder.Services.AddAntiforgery(a => a.Cookie.Name = "OAuthSim.Antiforgery");
        var host = builder.Build();
        host.UseExceptionHandler("/Home/Error");
        host.Use(async (context, next) =>
        {
            // The issuer is canonical and cannot be changed by a request's Host header.
            var expectedPort = new Uri(host.Urls.FirstOrDefault() ?? $"http://127.0.0.1:{requestedPort}").Port;
            if (context.Request.Host.Host is not ("localhost" or "127.0.0.1") || context.Request.Host.Port != expectedPort)
            { context.Response.StatusCode = 400; await context.Response.WriteAsync("Use the localhost URL printed by OAuthSim."); return; }
            context.Response.Headers.CacheControl = "no-cache, no-store";
            context.Response.Headers.Pragma = "no-cache";
            await next();
        });
        host.UseRouting();
        host.UseMiddleware<ProtocolCorsMiddleware>();
        host.MapControllers();
        host.MapControllerRoute("default", "{controller=Admin}/{action=Index}/{id?}");
        return host;
    }

    var app = BuildHost(port);
    try { await app.StartAsync(); }
    catch (IOException) when (options.Port is null)
    {
        await app.DisposeAsync();
        Console.WriteLine($"Port {port} is busy; selecting an available port.");
        app = BuildHost(0);
        await app.StartAsync();
    }
    await using (app)
    {
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        port = new Uri(address).Port;
        store.Update(s => s.Port = port);
        var issuer = $"http://localhost:{port}";
        Console.WriteLine($"OAuthSim 0.4.0\nAdmin:     {issuer}/\nDiscovery: {issuer}/.well-known/openid-configuration\nSettings:  {store.FilePath}");
        var clients = store.Read().Clients;
        if (clients.Count == 1)
        {
            Console.WriteLine($"Client ID: {clients[0].ClientId}");
            Console.WriteLine(clients[0].IsPublic ? "Public client: PKCE required" : $"Secret:    {clients[0].ClientSecret}");
        }
        if (!options.NoBrowser)
        {
            try
            {
                if (OperatingSystem.IsWindows()) Process.Start(new ProcessStartInfo(issuer) { UseShellExecute = true });
                else Process.Start(OperatingSystem.IsMacOS() ? "open" : "xdg-open", [issuer]);
            }
            catch (Exception ex) { Console.WriteLine($"Could not open a browser: {ex.Message}\nOpen {issuer} manually."); }
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
