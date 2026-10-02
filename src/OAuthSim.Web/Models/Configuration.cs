namespace OAuthSim.Web.Models;

public sealed class SimulatorSettings
{
    public int SchemaVersion { get; set; } = 1;
    public int Port { get; set; } = 42069;
    public string? DefaultClientId { get; set; }
    public int CodeLifetimeSeconds { get; set; } = 300;
    public int TokenLifetimeSeconds { get; set; } = 3600;
    public int RefreshLifetimeSeconds { get; set; } = 2592000;
    public string SigningPrivateKey { get; set; } = "";
    public string SigningKeyId { get; set; } = Guid.NewGuid().ToString("N");
    public List<OAuthClient> Clients { get; set; } = [];
}

public sealed class OAuthClient
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string Name { get; set; } = "Default client";
    public bool IsPublic { get; set; }
    public bool Enabled { get; set; } = true;
    public bool RelaxRedirects { get; set; }
    public bool RelaxScopes { get; set; }
    public List<string> RedirectUris { get; set; } = [];
    public List<string> Scopes { get; set; } = [];
    public List<MockUser> Users { get; set; } = [];
    public Dictionary<string, Dictionary<string, System.Text.Json.JsonElement>> ClaimsByScope { get; set; } = [];
    public LoginPreferences LastLogin { get; set; } = new();
}

public sealed class MockUser
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Email { get; set; } = "";
    public string Name { get; set; } = "";
    public string Country { get; set; } = "PH";
    public string Language { get; set; } = "en";
    public bool Enabled { get; set; } = true;
    // Scope -> claim name -> JSON value. Reserved protocol claims are never overridden.
    public Dictionary<string, Dictionary<string, System.Text.Json.JsonElement>> ClaimsByScope { get; set; } = [];
}

public sealed class LoginPreferences
{
    public string? UserId { get; set; }
    public string Email { get; set; } = "";
    public string Country { get; set; } = "PH";
    public string Language { get; set; } = "en";
}
