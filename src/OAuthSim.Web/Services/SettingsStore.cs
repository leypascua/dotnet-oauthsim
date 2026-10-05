using System.Security.Cryptography;
using System.Text.Json;
using OAuthSim.Web.Cli;
using OAuthSim.Web.Models;

namespace OAuthSim.Web.Services;

public sealed class SettingsStore : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly object gate = new();
    private readonly FileStream lease;
    private SimulatorSettings settings;
    public string FilePath { get; }

    public SettingsStore(string directory)
    {
        Directory.CreateDirectory(directory);
        FilePath = Path.Combine(directory, "settings.json");
        try { lease = new FileStream(Path.Combine(directory, "settings.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException ex) { throw new IOException("Another OAuthSim instance is using this settings directory. Use --settings-dir for an independent instance.", ex); }
        try
        {
            settings = File.Exists(FilePath)
                ? JsonSerializer.Deserialize<SimulatorSettings>(File.ReadAllText(FilePath), Json) ?? throw new JsonException("Settings document is null.")
                : new();
            Validate(settings);
        }
        catch
        {
            lease.Dispose();
            throw new InvalidOperationException($"Cannot load {FilePath}. Restore settings.json.bak or fix the document; the original file has been preserved.");
        }
    }

    public SimulatorSettings Read()
    {
        lock (gate) return Clone(settings);
    }

    public void Update(Action<SimulatorSettings> change)
    {
        lock (gate)
        {
            var next = Clone(settings);
            change(next);
            Validate(next);
            var temporary = FilePath + ".tmp";
            try
            {
                using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    JsonSerializer.Serialize(stream, next, Json);
                    stream.Flush(true);
                }
                if (File.Exists(FilePath)) File.Replace(temporary, FilePath, FilePath + ".bak");
                else File.Move(temporary, FilePath);
                settings = next;
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }

    // Resolve in memory; persist only after the host has successfully bound its port.
    public void ApplyStartup(Options options)
    {
        lock (gate)
        {
            var client = settings.Clients.FirstOrDefault(c => c.ClientId == options.ClientId)
                ?? (options.ClientId is null ? settings.Clients.FirstOrDefault(c => c.Id == settings.DefaultClientId) ?? settings.Clients.FirstOrDefault() : null);
            if (client is null)
            {
                client = new OAuthClient { ClientId = options.ClientId ?? "oauthsim-" + RandomValue(), ClientSecret = RandomValue() };
                settings.Clients.Add(client);
            }
            settings.DefaultClientId = client.Id;
            if (options.ClientSecret is not null)
            {
                client.ClientSecret = options.ClientSecret;
                client.IsPublic = false;
            }
            if (string.IsNullOrEmpty(client.ClientSecret) && !client.IsPublic) client.ClientSecret = RandomValue();
            if (options.Port is not null) settings.Port = options.Port.Value;
            if (string.IsNullOrEmpty(settings.SigningPrivateKey))
            {
                using var rsa = RSA.Create(2048);
                settings.SigningPrivateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
            }
        }
    }

    public static string RandomValue() => Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
    private static SimulatorSettings Clone(SimulatorSettings value) => JsonSerializer.Deserialize<SimulatorSettings>(JsonSerializer.Serialize(value, Json), Json)!;

    private static void Validate(SimulatorSettings value)
    {
        if (value.SchemaVersion != 1 || value.Port is < 1 or > 65535 || value.CodeLifetimeSeconds is < 1 or > 3600
            || value.TokenLifetimeSeconds is < 1 or > 86400 || value.RefreshLifetimeSeconds is < 1 or > 31536000)
            throw new InvalidOperationException("Unsupported schema or invalid port/token lifetimes.");
        if (value.Clients is null || value.Clients.Select(c => c.ClientId).Distinct(StringComparer.Ordinal).Count() != value.Clients.Count
            || value.Clients.Select(c => c.Id).Distinct(StringComparer.Ordinal).Count() != value.Clients.Count)
            throw new InvalidOperationException("Client IDs must be unique.");
        foreach (var c in value.Clients)
        {
            c.Issuer = string.IsNullOrWhiteSpace(c.Issuer) ? null : c.Issuer.Trim();
            c.AccessTokenAudience = string.IsNullOrWhiteSpace(c.AccessTokenAudience) ? null : c.AccessTokenAudience.Trim();
            if (c.Issuer is not null && (!Uri.TryCreate(c.Issuer, UriKind.Absolute, out var issuer)
                || issuer.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(issuer.UserInfo)
                || !string.IsNullOrEmpty(issuer.Query) || !string.IsNullOrEmpty(issuer.Fragment)))
                throw new InvalidOperationException("Issuer must be an absolute HTTP(S) URL without credentials, a query or a fragment.");
            if (string.IsNullOrWhiteSpace(c.ClientId) || c.Users is null || c.Scopes is null || c.RedirectUris is null || c.LastLogin is null
                || string.IsNullOrEmpty(c.Id) || (!c.IsPublic && c.ClientSecret is null)
                || c.Users.Select(u => u.Id).Distinct().Count() != c.Users.Count
                || c.Users.Any(u => string.IsNullOrEmpty(u.Id) || u.Email is null || u.Name is null || u.ClaimsByScope is null || u.ClaimsByScope.Any(p => p.Value is null))
                || c.ClaimsByScope is null || c.ClaimsByScope.Any(p => p.Value is null)
                || c.LastLogin.Email is null || c.Scopes.Any(s => s is null) || c.RedirectUris.Any(r => r is null))
                throw new InvalidOperationException("Invalid client configuration.");
            foreach (var redirect in c.RedirectUris) AuthorizationService.ValidateRedirect(new OAuthClient(), redirect);
            AuthorizationService.ValidateScopes(new OAuthClient(), c.Scopes.ToArray());
            foreach (var scope in c.ClaimsByScope.Keys) AuthorizationService.ValidateScopes(new OAuthClient(), [scope]);
        }
    }

    public void Dispose() => lease.Dispose();
}
