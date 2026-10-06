namespace OAuthSim.Web.Cli;

public sealed record Options(int? Port, string? ClientId, string? ClientSecret, bool NoBrowser, string SettingsDirectory,
    string? PublicBaseUrl = null, string[]? TrustedProxies = null, bool Hosted = false)
{
    public const string Help = """
        OAuthSim — local OAuth 2.0 / OpenID Connect server

        dotnet oauth-sim [--port 42069] [--clientId <id>] [--clientSecret <secret>]
                         [--no-browser] [--settings-dir <directory>]
                         [--public-base-url <http(s)://host[/path]>]
                         [--trusted-proxy <IP or CIDR>] [--hosted]

        Options override saved settings and are persisted after successful startup.
        Default settings directory: ~/.oauth-sim
        --public-base-url  Public endpoint URL and default issuer (OAUTHSIM_PUBLIC_BASE_URL)
        --trusted-proxy    Repeat for trusted forwarding proxies/networks; default: loopback
                           Also accepts OAUTHSIM_TRUSTED_PROXIES (comma-separated)
        --hosted           Use IIS / ASP.NET Core bindings instead of the local CLI listener
                           Requires a public base URL; incompatible with --port
        --help      Show this help
        --version   Show the version
        """;

    public static Options Parse(string[] args)
    {
        int? port = null;
        string? id = null, secret = null;
        var noBrowser = false;
        var hosted = false;
        var publicBaseUrl = Environment.GetEnvironmentVariable("OAUTHSIM_PUBLIC_BASE_URL");
        var proxies = new List<string>();
        var proxyEnvironment = Environment.GetEnvironmentVariable("OAUTHSIM_TRUSTED_PROXIES");
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".oauth-sim");
        for (var i = 0; i < args.Length; i++)
        {
            var name = args[i];
            if (name == "--no-browser") { noBrowser = true; continue; }
            if (name == "--hosted") { hosted = true; continue; }
            var equals = name.IndexOf('=');
            string value;
            if (equals >= 0) { value = name[(equals + 1)..]; name = name[..equals]; }
            else if (++i < args.Length && !args[i].StartsWith("--")) value = args[i];
            else throw new ArgumentException($"Missing value for {name}.");
            if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException($"{name} cannot be empty.");
            switch (name)
            {
                case "--port":
                    if (!int.TryParse(value, out var number) || number is < 1 or > 65535)
                        throw new ArgumentException("Port must be between 1 and 65535.");
                    port = number;
                    break;
                case "--clientId": id = value; break;
                case "--clientSecret": secret = value; break;
                case "--settings-dir": directory = Path.GetFullPath(value); break;
                case "--public-base-url": publicBaseUrl = value; break;
                case "--trusted-proxy": proxies.Add(value); break;
                default: throw new ArgumentException($"Unknown option: {name}.");
            }
        }
        if (hosted && port is not null) throw new ArgumentException("--hosted and --port cannot be combined.");
        return new(port, id, secret, noBrowser, directory, publicBaseUrl,
            proxies.Count > 0 ? proxies.ToArray() : proxyEnvironment?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries), hosted);
    }
}
