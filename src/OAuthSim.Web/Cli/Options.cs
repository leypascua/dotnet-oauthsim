namespace OAuthSim.Web.Cli;

public sealed record Options(int? Port, string? ClientId, string? ClientSecret, bool NoBrowser, string SettingsDirectory)
{
    public const string Help = """
        OAuthSim — local OAuth 2.0 / OpenID Connect server

        dotnet oauth-sim [--port 42069] [--clientId <id>] [--clientSecret <secret>]
                         [--no-browser] [--settings-dir <directory>]

        Options override saved settings and are persisted after successful startup.
        Default settings directory: ~/.oauth-sim
        --help      Show this help
        --version   Show the version
        """;

    public static Options Parse(string[] args)
    {
        int? port = null;
        string? id = null, secret = null;
        var noBrowser = false;
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".oauth-sim");
        for (var i = 0; i < args.Length; i++)
        {
            var name = args[i];
            if (name == "--no-browser") { noBrowser = true; continue; }
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
                default: throw new ArgumentException($"Unknown option: {name}.");
            }
        }
        return new(port, id, secret, noBrowser, directory);
    }
}
