using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OAuthSim.Web.Cli;
using OAuthSim.Web.Models;
using OAuthSim.Web.Services;

// Dependency-free integration runner: dotnet run --project tests/OAuthSim.Tests -c Release
// Optional executable argument tests the installed tool rather than the project DLL.
var directory = Path.Combine(Path.GetTempPath(), "oauthsim-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
var checks = 0;
void Check(bool condition, string name)
{
    if (!condition) throw new Exception("FAILED: " + name);
    Console.WriteLine("PASS " + name);
    checks++;
}
void Throws(Action action, string name)
{
    try { action(); } catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or ProtocolException)
    { Check(true, name); return; }
    Check(false, name);
}

Check(Options.Parse(["--port", "42069", "--clientId=abc", "--no-browser"]).ClientId == "abc", "CLI accepts exact options and equals syntax");
Throws(() => Options.Parse(["--port", "0"]), "CLI rejects invalid port");
Throws(() => Options.Parse(["--unknown", "x"]), "CLI rejects unknown option");

var storeDirectory = Path.Combine(directory, "store");
using (var store = new SettingsStore(storeDirectory))
{
    store.ApplyStartup(new(null, "test-client", "test-secret", true, storeDirectory));
    store.Update(s => s.Port = 42069);
    Throws(() => { using var duplicate = new SettingsStore(storeDirectory); }, "settings directory enforces exclusive lock");
    Throws(() => store.Update(s => s.TokenLifetimeSeconds = 0), "invalid settings update rolls back");
    Check(store.Read().TokenLifetimeSeconds == 3600, "settings remain intact after failed update");
    foreach (var invalidIssuer in new[] { "relative/path", "ftp://identity.example.com", "https://user:pass@identity.example.com", "https://identity.example.com?tenant=1", "https://identity.example.com#tenant" })
        Throws(() => store.Update(s => s.Clients[0].Issuer = invalidIssuer), "settings reject invalid issuer: " + invalidIssuer);
    Check(store.Read().Clients[0].Issuer is null, "invalid issuer updates leave settings intact");
    var auth = new AuthorizationService(store);
    var request = auth.Create("test-client", "http://localhost:3000/callback", ["openid", "email"], "state", "nonce", null, null, "query");
    var identity = new Identity("subject", "user@example.com", "User", "PH", "en", []);
    var code = auth.IssueCode(request, identity, request.Scopes);
    var races = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
    {
        try { auth.Exchange(code, "test-client", request.RedirectUri, null); return true; }
        catch (ProtocolException) { return false; }
    })));
    Check(races.Count(x => x) == 1, "authorization code is consumed atomically");
    store.Update(s => s.CodeLifetimeSeconds = 1);
    var expiring = auth.Create("test-client", request.RedirectUri, [], null, null, null, null, "query");
    var expired = auth.IssueCode(expiring, identity, []);
    await Task.Delay(1100);
    Throws(() => auth.Exchange(expired, "test-client", request.RedirectUri, null), "expired code is rejected");
    using var tokenService = new TokenService(store);
    var issued = tokenService.Issue(new("test-client", request.RedirectUri, ["email"], identity, null, null, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5)));
    var jwt = issued.AccessToken;
    var validated = tokenService.ValidateAccess(jwt);
    Check(validated.Jwt.Subject == identity.Subject && validated.Jwt.Issuer == tokenService.Issuer
        && validated.Jwt.Audience == "test-client" && validated.Jwt.ExpiresAt - validated.Jwt.IssuedAt == 3600
        && validated.Access.ClientId == "test-client" && validated.Access.Scope == "email"
        && validated.Profile.Email == identity.Email && validated.Simulator.TokenUse == "access"
        && validated.Simulator.GrantType == "authorization_code" && validated.CustomClaims.Count == 0,
        "validated access token exposes segregated typed claims");
    var scopedIdentity = identity with
    {
        ClaimsByScope = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, JsonElement>>>(
            """{"roles":{"role":"tester","details":{"enabled":true},"iss":"forged","sub":"forged","nbf":1,"nonce":"forged","email":"forged","country":"forged","token_use":"forged","grant_type":"forged"}}""")!
    };
    var scopedAccess = tokenService.Issue(new("test-client", request.RedirectUri, ["email", "profile", "roles"], scopedIdentity,
        null, null, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5))).AccessToken;
    var scopedValidated = tokenService.ValidateAccess(scopedAccess);
    Check(scopedValidated.Profile.Name == identity.Name && scopedValidated.Profile.Locale == "en-PH"
        && scopedValidated.Simulator.Country == "PH" && scopedValidated.Simulator.Language == "en"
        && scopedValidated.Jwt.Subject == identity.Subject && scopedValidated.Jwt.NotBefore is null
        && scopedValidated.Authentication.Nonce is null && scopedValidated.CustomClaims.Count == 2
        && scopedValidated.CustomClaims["details"].GetProperty("enabled").GetBoolean(),
        "custom claims cannot override typed JWT, OIDC, or simulator fields");
    var scopedWire = scopedValidated.ToClaims();
    Check(scopedWire["country"].GetString() == "PH" && scopedWire["role"].GetString() == "tester"
        && !scopedWire.ContainsKey("Jwt") && !scopedWire.ContainsKey("Simulator") && !scopedWire.ContainsKey("CustomClaims"),
        "segregated claim groups flatten to the existing wire format");
    Throws(() => tokenService.ValidateAccess(jwt[..^8] + "AAAAAAAA"), "tampered JWT rejected");
    var clock = new TestClock();
    var sessions = new LoginSessionService(new SecurityState(), clock);
    var client = store.Read().Clients[0];
    var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
    var sessionIdentity = identity with { Subject = "adhoc-test" };
    sessions.Create(context, client, sessionIdentity, clock.GetUtcNow());
    var cookie = context.Response.Headers.SetCookie.Last(s => s!.Contains("max-age=900"))!.Split(';')[0];
    context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
    context.Request.Headers.Cookie = cookie;
    clock.Advance(TimeSpan.FromMinutes(14));
    var renewed = sessions.Get(context, client, true);
    Check(renewed is not null && renewed.AuthTime == clock.Initial && renewed.ExpiresAt == clock.GetUtcNow().AddMinutes(15), "session slides at 14 minutes without changing original auth_time");
    clock.Advance(TimeSpan.FromMinutes(2));
    Check(sessions.Get(context, client) is not null, "sliding session survives original expiration");
    Check(sessions.Get(context, new OAuthClient { ClientId = "other" }) is null, "session cannot cross client boundaries");
    Check(sessions.Get(context, new OAuthClient { Id = client.Id, ClientId = client.ClientId, Enabled = false }) is null, "disabled client invalidates login session");
    sessions.Create(context, client, sessionIdentity, clock.GetUtcNow());
    var freshCookie = context.Response.Headers.SetCookie.Last(s => s!.Contains("max-age=900"))!.Split(';')[0];
    context = new Microsoft.AspNetCore.Http.DefaultHttpContext(); context.Request.Headers.Cookie = freshCookie;
    clock.Advance(TimeSpan.FromMinutes(15));
    Check(sessions.Get(context, client) is null, "session expires at 15 minutes of inactivity");
    client.Users.Add(new MockUser { Id = "configured", Email = "updated@example.com", Name = "Updated", ClaimsByScope = [] });
    sessions.Create(context, client, identity with { Subject = "configured" }, clock.GetUtcNow());
    context.Request.Headers.Cookie = context.Response.Headers.SetCookie.Last(s => s!.Contains("max-age=900"))!.Split(';')[0];
    Check(sessions.Get(context, client)?.Identity.Name == "Updated", "session resolves current configured-user profile");
    client.Users[0].Enabled = false;
    Check(sessions.Get(context, client) is null, "disabled user invalidates existing session");
    client.Users[0].Enabled = true;
    sessions.Create(context, client, identity with { Subject = "configured" }, clock.GetUtcNow());
    context.Request.Headers.Cookie = context.Response.Headers.SetCookie.Last(s => s!.Contains("max-age=900"))!.Split(';')[0];
    client.Users.Clear();
    Check(sessions.Get(context, client) is null, "deleted last configured user cannot become an ad-hoc session");
    var oldKid = store.Read().SigningKeyId;
    var oldRefresh = tokenService.Issue(new("test-client", request.RedirectUri, ["offline_access"], identity, null, null, clock.Initial, clock.Initial.AddMinutes(5))).RefreshToken!;
    tokenService.InvalidateAll();
    Check(store.Read().SigningKeyId != oldKid, "global invalidation rotates persisted signing key ID");
    Throws(() => tokenService.ValidateAccess(jwt), "global invalidation rejects old JWT");
    Throws(() => tokenService.Refresh(oldRefresh, "test-client", null), "global invalidation rejects old refresh token");
    Check(File.Exists(store.FilePath + ".bak"), "atomic settings writes retain backup");
    store.Update(s => { s.Clients[0].Issuer = " https://identity.example.com/tenant/ "; s.Clients[0].AccessTokenAudience = " orders-api "; });
}
using (var store = new SettingsStore(storeDirectory)) Check(store.Read().Clients[0].ClientSecret == "test-secret", "settings survive reopening");
using (var store = new SettingsStore(storeDirectory)) Check(store.Read().Clients[0].Issuer == "https://identity.example.com/tenant/"
    && store.Read().Clients[0].AccessTokenAudience == "orders-api", "token identity overrides normalize whitespace and survive reopening");
var legacy = JsonDocument.Parse(File.ReadAllText(Path.Combine(storeDirectory, "settings.json"))).RootElement;
var legacyDocument = System.Text.Json.Nodes.JsonNode.Parse(legacy.GetRawText())!;
legacyDocument["clients"]![0]!.AsObject().Remove("claimsByScope");
legacyDocument["clients"]![0]!.AsObject().Remove("requireIntrospectionBasicAuthentication");
legacyDocument["clients"]![0]!.AsObject().Remove("issuer");
legacyDocument["clients"]![0]!.AsObject().Remove("accessTokenAudience");
File.WriteAllText(Path.Combine(storeDirectory, "settings.json"), legacyDocument.ToJsonString());
using (var store = new SettingsStore(storeDirectory)) Check(store.Read().Clients[0].ClaimsByScope.Count == 0, "older settings without application claims remain compatible");
using (var store = new SettingsStore(storeDirectory)) Check(store.Read().Clients[0].RequireIntrospectionBasicAuthentication, "older settings default to requiring Basic introspection authentication");
using (var store = new SettingsStore(storeDirectory)) Check(store.Read().Clients[0].Issuer is null && store.Read().Clients[0].AccessTokenAudience is null,
    "older settings leave issuer and audience overrides unset");
var invalidIdentityDirectory = Path.Combine(directory, "invalid-identity");
Directory.CreateDirectory(invalidIdentityDirectory);
legacyDocument["clients"]![0]!["issuer"] = "https://identity.example.com?tenant=1";
var invalidIdentityJson = legacyDocument.ToJsonString();
File.WriteAllText(Path.Combine(invalidIdentityDirectory, "settings.json"), invalidIdentityJson);
Throws(() => { using var bad = new SettingsStore(invalidIdentityDirectory); }, "invalid persisted issuer prevents startup");
Check(File.ReadAllText(Path.Combine(invalidIdentityDirectory, "settings.json")) == invalidIdentityJson, "invalid issuer settings are preserved on load failure");
var corruptDirectory = Path.Combine(directory, "corrupt");
Directory.CreateDirectory(corruptDirectory);
File.WriteAllText(Path.Combine(corruptDirectory, "settings.json"), "{broken");
Throws(() => { using var bad = new SettingsStore(corruptDirectory); }, "malformed settings fail without replacement");
Check(File.ReadAllText(Path.Combine(corruptDirectory, "settings.json")) == "{broken", "malformed settings preserved");

var listener = new TcpListener(IPAddress.Loopback, 0);
listener.Start();
var port = ((IPEndPoint)listener.LocalEndpoint).Port;
listener.Stop();
var settingsDirectory = Path.Combine(directory, "http");
var baseUrl = $"http://localhost:{port}";
var handler = new HttpClientHandler { AllowAutoRedirect = false, CookieContainer = new CookieContainer() };
using var http = new HttpClient(handler) { BaseAddress = new Uri(baseUrl), Timeout = TimeSpan.FromSeconds(15) };
var output = new StringBuilder();
Process? server = null;
Process Start(params string[] extra)
{
    var start = new ProcessStartInfo { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, WorkingDirectory = directory };
    if (args.Length > 0) start.FileName = Path.GetFullPath(args[0]);
    else
    {
        start.FileName = "dotnet";
        start.ArgumentList.Add(typeof(SettingsStore).Assembly.Location);
    }
    start.ArgumentList.Add("--settings-dir"); start.ArgumentList.Add(settingsDirectory);
    start.ArgumentList.Add("--no-browser");
    foreach (var item in extra) start.ArgumentList.Add(item);
    var process = Process.Start(start)!;
    process.OutputDataReceived += (_, e) => { lock (output) output.AppendLine(e.Data); };
    process.ErrorDataReceived += (_, e) => { lock (output) output.AppendLine(e.Data); };
    process.BeginOutputReadLine(); process.BeginErrorReadLine();
    return process;
}
async Task Ready()
{
    for (var i = 0; i < 80; i++)
    {
        if (server!.HasExited) throw new Exception("Server exited: " + output);
        try { if ((await http.GetAsync("/.well-known/openid-configuration")).IsSuccessStatusCode) return; } catch (HttpRequestException) { }
        await Task.Delay(100);
    }
    throw new Exception("Server not ready: " + output);
}
void Stop()
{
    if (server is null) return;
    if (!server.HasExited) server.Kill(true);
    server.WaitForExit(); server.Dispose(); server = null;
}
static string Field(string html, string name)
{
    var tag = Regex.Matches(html, "<input[^>]*>", RegexOptions.IgnoreCase).Select(m => m.Value)
        .First(t => t.Contains($"name=\"{name}\""));
    return WebUtility.HtmlDecode(Regex.Match(tag, "value=\"([^\"]*)\"").Groups[1].Value);
}
async Task<HttpResponseMessage> Post(string path, Dictionary<string, string> fields, bool admin = false)
{
    if (admin)
    {
        var page = await http.GetStringAsync("/");
        fields["__RequestVerificationToken"] = Field(page, "__RequestVerificationToken");
    }
    return await http.PostAsync(path, new FormUrlEncodedContent(fields));
}
async Task<JsonElement> Json(HttpResponseMessage response) => JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
const string callback = "http://localhost:3000/callback?existing=1";
const string verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
var challenge = TokenService.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
async Task<(string Code, HttpResponseMessage Response)> Login(string client = "test-client", string? user = null, string scope = "openid profile email offline_access", string mode = "query", string pkce = "")
{
    var url = QueryHelpers.AddQueryString("/oauth/v2/authorize", new Dictionary<string, string?>
    {
        ["response_type"] = "code", ["client_id"] = client, ["redirect_uri"] = callback, ["scope"] = scope,
        ["state"] = "state+&=with spaces", ["nonce"] = "test-nonce", ["response_mode"] = mode, ["prompt"] = "login"
    });
    if (pkce.Length > 0) url = QueryHelpers.AddQueryString(url, new Dictionary<string, string?> { ["code_challenge"] = pkce, ["code_challenge_method"] = "S256" });
    var page = await http.GetAsync(url);
    Check(page.IsSuccessStatusCode, "authorization login renders: " + client);
    var html = await page.Content.ReadAsStringAsync();
    var response = await Post("/oauth/v2/authorize", new()
    {
        ["transactionId"] = Field(html, "transactionId"), ["__RequestVerificationToken"] = Field(html, "__RequestVerificationToken"),
        ["email"] = "person@example.com", ["userId"] = user ?? "", ["country"] = "PH", ["language"] = "fil", ["scopes"] = scope, ["decision"] = "allow"
    });
    if (mode == "form_post") return (Field(await response.Content.ReadAsStringAsync(), "code"), response);
    Check(response.StatusCode == HttpStatusCode.Redirect, "login returns callback redirect");
    var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
    Check(query["state"] == "state+&=with spaces" && query["existing"] == "1", "state and existing redirect query preserved");
    return (query["code"].ToString(), response);
}
Dictionary<string, string> ExchangeFields(string code, string client = "test-client", string secret = "test-secret", string? proof = null) => new()
{
    ["grant_type"] = "authorization_code", ["client_id"] = client, ["client_secret"] = secret,
    ["redirect_uri"] = callback, ["code"] = code, ["code_verifier"] = proof ?? ""
};

try
{
    server = Start("--port", port.ToString(), "--clientId", "test-client", "--clientSecret", "test-secret");
    await Ready();
    var dashboard = await http.GetStringAsync("/");
    Check(dashboard.Contains("Server administration") && dashboard.Contains("htmx.org@2.0.11"), "packaged admin page and CDN references render");
    Check((await Post("/Admin/SaveSettings", new() { ["codeLifetimeSeconds"] = "100" })).StatusCode == HttpStatusCode.BadRequest, "admin mutations require antiforgery token");
    var metadata = await Json(await http.GetAsync("/.well-known/openid-configuration"));
    Check(metadata.GetProperty("issuer").GetString() == baseUrl, "discovery uses canonical issuer");
    Check(metadata.GetProperty("grant_types_supported").EnumerateArray().Any(g => g.GetString() == "client_credentials"), "discovery advertises client credentials");
    Check(metadata.GetProperty("introspection_endpoint").GetString() == baseUrl + "/oauth/v2/introspect"
        && metadata.GetProperty("introspection_endpoint_auth_methods_supported").EnumerateArray().Select(a => a.GetString()).SequenceEqual(new[] { "client_secret_basic" }), "discovery advertises Basic-only introspection authentication");
    Check(dashboard.Contains("Token introspection") && dashboard.Contains("token=&lt;access-token&gt;"), "admin renders introspection example with placeholders");
    Check(dashboard.Contains("name=\"requireIntrospectionBasicAuthentication\"") && dashboard.Contains("-u &quot;test-client:"), "admin renders per-client switch and Basic introspection example");
    Check(dashboard.Contains("Scope mappings") && dashboard.Contains("Alpine.data('applicationClaims'")
        && dashboard.Contains("x-ref=\"payload\"") && !dashboard.Contains("Claims by scope (JSON)"), "admin renders application claims editor with compatible hidden payload");
    Check(dashboard.Contains("Token identity") && dashboard.Contains("name=\"issuer\"") && dashboard.Contains("name=\"accessTokenAudience\"")
        && dashboard.Contains("Default issuer") && dashboard.Contains("ID-token audience"), "admin renders optional token identity controls and effective values");
    var jwks = await Json(await http.GetAsync("/oauth/v2/jwks"));
    Check(jwks.GetProperty("keys")[0].GetProperty("kty").GetString() == "RSA", "JWKS publishes RSA public key");
    var first = await Login();
    var wrong = await Post("/token", ExchangeFields(first.Code, secret: "wrong"));
    Check(wrong.StatusCode == HttpStatusCode.Unauthorized, "wrong client secret rejected");
    var tokenResponse = await Post("/token", ExchangeFields(first.Code));
    Check(tokenResponse.IsSuccessStatusCode, "authorization code exchange succeeds");
    var issued = await Json(tokenResponse);
    var access = issued.GetProperty("access_token").GetString()!;
    var idToken = issued.GetProperty("id_token").GetString()!;
    var refresh = issued.GetProperty("refresh_token").GetString()!;
    using (var key = RSA.Create())
    {
        static byte[] Decode(string v) => Convert.FromBase64String(v.Replace('-', '+').Replace('_', '/') + new string('=', (4 - v.Length % 4) % 4));
        var publicKey = jwks.GetProperty("keys")[0];
        key.ImportParameters(new RSAParameters { Modulus = Decode(publicKey.GetProperty("n").GetString()!), Exponent = Decode(publicKey.GetProperty("e").GetString()!) });
        var pieces = idToken.Split('.');
        Check(key.VerifyData(Encoding.ASCII.GetBytes(pieces[0] + "." + pieces[1]), Decode(pieces[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), "ID token signature validates using JWKS");
        var payload = JsonDocument.Parse(Decode(pieces[1])).RootElement;
        Check(payload.GetProperty("nonce").GetString() == "test-nonce" && payload.GetProperty("aud").GetString() == "test-client", "ID token binds nonce and audience");
        Check(!payload.TryGetProperty("state", out _) && !Payload(access).TryGetProperty("state", out _), "authorization state is not propagated into tokens");
    }
    var replay = await Json(await Post("/token", ExchangeFields(first.Code)));
    Check(replay.GetProperty("error").GetString() == "invalid_grant", "code replay rejected over HTTP");
    async Task<HttpResponseMessage> Userinfo(string jwt)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/userinfo");
        request.Headers.Authorization = new("Bearer", jwt);
        return await http.SendAsync(request);
    }
    var profile = await Json(await Userinfo(access));
    Check(profile.GetProperty("email").GetString() == "person@example.com" && profile.GetProperty("locale").GetString() == "fil-PH", "userinfo returns scoped identity and locale");
    Check((await Userinfo(idToken)).StatusCode == HttpStatusCode.Unauthorized, "userinfo rejects ID token as bearer access token");
    async Task<HttpResponseMessage> Introspect(string jwt, string client = "test-client", string secret = "test-secret", bool basic = true, string path = "/oauth/v2/introspect", string? hint = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path);
        var fields = new Dictionary<string, string> { ["token"] = jwt };
        if (hint is not null) fields["token_type_hint"] = hint;
        if (basic) request.Headers.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(WebUtility.UrlEncode(client) + ":" + WebUtility.UrlEncode(secret))));
        else { fields["client_id"] = client; fields["client_secret"] = secret; }
        request.Content = new FormUrlEncodedContent(fields);
        return await http.SendAsync(request);
    }
    var inspectedResponse = await Introspect(access);
    async Task<HttpResponseMessage> AnonymousIntrospect(string jwt, string path = "/oauth/v2/introspect", string? claimedClient = null)
    {
        var fields = new Dictionary<string, string> { ["token"] = jwt };
        if (claimedClient is not null) fields["client_id"] = claimedClient;
        return await Post(path, fields);
    }
    var needsBasic = await AnonymousIntrospect(access);
    Check(needsBasic.StatusCode == HttpStatusCode.Unauthorized && needsBasic.Headers.WwwAuthenticate.ToString().Contains("Basic")
        && (await Json(needsBasic)).GetProperty("error").GetString() == "invalid_client", "default ON switch requires Basic for valid anonymous tokens");
    Check((await Introspect(access, basic: false)).StatusCode == HttpStatusCode.BadRequest, "introspection no longer accepts form-based client-secret authentication");
    var inspected = await Json(inspectedResponse);
    Check(inspectedResponse.IsSuccessStatusCode && inspected.GetProperty("active").GetBoolean()
        && inspected.GetProperty("token_type").GetString() == "Bearer" && inspected.GetProperty("email").GetString() == "person@example.com"
        && inspected.GetProperty("exp").ValueKind == JsonValueKind.Number && inspected.GetProperty("client_id").GetString() == "test-client", "introspection returns validated user claims and metadata");
    Check(inspectedResponse.Headers.CacheControl?.NoStore == true && inspectedResponse.Headers.Pragma.Any(p => p.Name == "no-cache"), "introspection disables response caching");
    Check((await Json(await Introspect(access, basic: true, path: "/introspect", hint: "unfamiliar"))).GetProperty("active").GetBoolean(), "introspection alias accepts Basic authentication and advisory hints");
    foreach (var invalid in new[] { idToken, refresh, "not-a-token", "bnVsbA.e30.AAAA", access[..^8] + "AAAAAAAA" })
    {
        var response = await Introspect(invalid);
        Check(response.StatusCode == HttpStatusCode.OK && (await Json(response)).GetRawText() == "{\"active\":false}", "unsupported or invalid token returns only inactive metadata");
        var anonymous = await AnonymousIntrospect(invalid);
        Check(anonymous.StatusCode == HttpStatusCode.OK && (await Json(anonymous)).GetRawText() == "{\"active\":false}", "unidentifiable anonymous token returns inactive even with Basic required");
    }
    // Sign pathological tokens using this isolated server's key to exercise validation beyond signature checks.
    string SignInspectionToken(string payload)
    {
        var saved = JsonDocument.Parse(File.ReadAllText(Path.Combine(settingsDirectory, "settings.json"))).RootElement;
        using var key = RSA.Create();
        key.ImportPkcs8PrivateKey(Convert.FromBase64String(saved.GetProperty("signingPrivateKey").GetString()!), out _);
        var header = TokenService.Base64Url(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", typ = "at+jwt", kid = saved.GetProperty("signingKeyId").GetString() }));
        var input = header + "." + TokenService.Base64Url(Encoding.UTF8.GetBytes(payload));
        return input + "." + TokenService.Base64Url(key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }
    var expiredPayload = System.Text.Json.Nodes.JsonNode.Parse(inspected.GetRawText())!;
    expiredPayload["exp"] = DateTimeOffset.UtcNow.AddSeconds(-1).ToUnixTimeSeconds();
    foreach (var payload in new[] { "null", "{}", "[]", expiredPayload.ToJsonString() })
    {
        Check((await Json(await Introspect(SignInspectionToken(payload)))).GetRawText() == "{\"active\":false}", "signed malformed or expired token returns inactive");
        Check((await Json(await AnonymousIntrospect(SignInspectionToken(payload)))).GetRawText() == "{\"active\":false}", "signed malformed or expired anonymous token returns inactive");
    }
    var validPayload = System.Text.Json.Nodes.JsonNode.Parse(inspected.GetRawText())!.AsObject();
    validPayload.Remove("active");
    validPayload.Remove("token_type");
    foreach (var claim in new[] { "iss", "exp", "token_use", "client_id", "aud" })
    {
        foreach (var variant in new[] { "missing", "null", "wrong type" })
        {
            var malformed = validPayload.DeepClone().AsObject();
            if (variant == "missing") malformed.Remove(claim);
            else malformed[claim] = variant == "null" ? null : System.Text.Json.Nodes.JsonValue.Create(true);
            Check((await Json(await Introspect(SignInspectionToken(malformed.ToJsonString())))).GetRawText() == "{\"active\":false}",
                $"typed validation rejects {variant} required claim {claim}");
        }
    }
    var optionalClaims = new[] { "sub", "iat", "nbf", "jti", "scope", "nonce", "auth_time", "at_hash", "email", "name", "locale", "grant_type", "country", "language" };
    foreach (var claim in optionalClaims)
    {
        var malformed = validPayload.DeepClone().AsObject();
        malformed[claim] = true;
        Check((await Json(await Introspect(SignInspectionToken(malformed.ToJsonString())))).GetRawText() == "{\"active\":false}",
            "typed validation rejects malformed known claim " + claim);
    }
    var minimalPayload = validPayload.DeepClone().AsObject();
    foreach (var claim in optionalClaims) minimalPayload.Remove(claim);
    var minimalInspection = await Json(await Introspect(SignInspectionToken(minimalPayload.ToJsonString())));
    Check(minimalInspection.GetProperty("active").GetBoolean() && optionalClaims.All(c => !minimalInspection.TryGetProperty(c, out _)),
        "known optional claims remain optional and absent on the wire");
    var nullablePayload = validPayload.DeepClone().AsObject();
    foreach (var claim in optionalClaims) nullablePayload[claim] = null;
    nullablePayload["custom_null"] = null;
    var nullableAccess = SignInspectionToken(nullablePayload.ToJsonString());
    var nullableInspection = await Json(await Introspect(nullableAccess));
    Check(nullableInspection.GetProperty("active").GetBoolean()
        && optionalClaims.All(c => nullableInspection.GetProperty(c).ValueKind == JsonValueKind.Null)
        && nullableInspection.GetProperty("custom_null").ValueKind == JsonValueKind.Null,
        "typed claim mapping preserves explicit optional and custom nulls");
    var nullableProfile = await Json(await Userinfo(nullableAccess));
    Check(nullableProfile.GetProperty("sub").ValueKind == JsonValueKind.Null
        && nullableProfile.GetProperty("email").ValueKind == JsonValueKind.Null
        && nullableProfile.GetProperty("country").ValueKind == JsonValueKind.Null
        && nullableProfile.GetProperty("custom_null").ValueKind == JsonValueKind.Null
        && !nullableProfile.TryGetProperty("grant_type", out _) && !nullableProfile.TryGetProperty("scope", out _),
        "userinfo preserves explicit identity nulls while excluding token metadata");
    foreach (var credentials in new[] { ("test-client", "wrong"), ("test-client", ""), ("unknown", "secret"), ("", "") })
    {
        var response = await Introspect(access, credentials.Item1, credentials.Item2);
        Check(response.StatusCode == HttpStatusCode.Unauthorized && response.Headers.WwwAuthenticate.ToString().Contains("Basic")
            && (await Json(response)).GetProperty("error").GetString() == "invalid_client", "introspection rejects invalid credentials with Basic challenge");
    }
    async Task CheckInspectionError(HttpRequestMessage request, string error, HttpStatusCode status = HttpStatusCode.BadRequest)
    {
        using (request)
        {
            var response = await http.SendAsync(request);
            Check(response.StatusCode == status && (await Json(response)).GetProperty("error").GetString() == error, "introspection rejects " + error + " request");
        }
    }
    foreach (var body in new[] { "client_id=test-client&client_secret=test-secret", "client_id=test-client&client_secret=test-secret&token=%20", "client_id=test-client&client_secret=test-secret&token=a&token=b", "client_id=test-client&client_id=test-client&client_secret=test-secret&token=a" })
        await CheckInspectionError(new(HttpMethod.Post, "/introspect") { Content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded") }, "invalid_request");
    await CheckInspectionError(new(HttpMethod.Post, "/introspect") { Content = new StringContent("{}", Encoding.UTF8, "application/json") }, "invalid_request");
    foreach (var auth in new[] { "Basic !!!", "Bearer " + access, "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("no-colon")), "Basic " + Convert.ToBase64String(new byte[] { 0xff, 0x3a, 0xff }) })
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/introspect") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = access }) };
        request.Headers.TryAddWithoutValidation("Authorization", auth);
        await CheckInspectionError(request, "invalid_client", HttpStatusCode.Unauthorized);
    }
    foreach (var fields in new[] {
        new Dictionary<string, string> { ["token"] = access, ["client_secret"] = "test-secret" },
        new Dictionary<string, string> { ["token"] = access, ["client_id"] = "conflicting" } })
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/introspect") { Content = new FormUrlEncodedContent(fields) };
        request.Headers.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));
        await CheckInspectionError(request, fields.ContainsKey("client_secret") ? "invalid_request" : "invalid_client", fields.ContainsKey("client_secret") ? HttpStatusCode.BadRequest : HttpStatusCode.Unauthorized);
    }
    static JsonElement Payload(string jwt)
    {
        var part = jwt.Split('.')[1];
        return JsonDocument.Parse(Convert.FromBase64String(part.Replace('-', '+').Replace('_', '/') + new string('=', (4 - part.Length % 4) % 4))).RootElement.Clone();
    }
    Dictionary<string, string> MachineFields(string? scope = "api.read", string client = "test-client", string secret = "test-secret")
    {
        var fields = new Dictionary<string, string> { ["grant_type"] = "client_credentials", ["client_id"] = client, ["client_secret"] = secret };
        if (scope is not null) fields["scope"] = scope;
        return fields;
    }
    var machineResponse = await Post("/oauth/v2/token", MachineFields());
    Check(machineResponse.IsSuccessStatusCode, "client credentials succeeds with POST authentication and unconfigured scopes");
    var machine = await Json(machineResponse);
    var machineAccess = machine.GetProperty("access_token").GetString()!;
    Check((await Json(await Introspect(machineAccess, basic: true))).GetProperty("grant_type").GetString() == "client_credentials", "introspection supports machine access tokens");
    var machinePayload = Payload(machineAccess);
    Check(machine.GetProperty("token_type").GetString() == "Bearer" && machine.GetProperty("expires_in").GetInt32() == 3600
        && !machine.TryGetProperty("id_token", out _) && !machine.TryGetProperty("refresh_token", out _), "client credentials returns access token only with configured lifetime");
    Check(machinePayload.GetProperty("sub").GetString() == "test-client" && machinePayload.GetProperty("aud").GetString() == "test-client"
        && machinePayload.GetProperty("iss").GetString() == baseUrl && machinePayload.GetProperty("grant_type").GetString() == "client_credentials"
        && machinePayload.GetProperty("scope").GetString() == "api.read" && machinePayload.GetProperty("exp").GetInt64() - machinePayload.GetProperty("iat").GetInt64() == 3600,
        "machine JWT contains client identity, scope, issuer, and expiry");
    Check(!machinePayload.TryGetProperty("email", out _) && !machinePayload.TryGetProperty("name", out _)
        && !machinePayload.TryGetProperty("country", out _) && !machinePayload.TryGetProperty("nonce", out _), "machine tokens contain no user-profile claims");
    using (var publicKey = RSA.Create())
    {
        static byte[] Decode(string v) => Convert.FromBase64String(v.Replace('-', '+').Replace('_', '/') + new string('=', (4 - v.Length % 4) % 4));
        var key = jwks.GetProperty("keys")[0];
        publicKey.ImportParameters(new RSAParameters { Modulus = Decode(key.GetProperty("n").GetString()!), Exponent = Decode(key.GetProperty("e").GetString()!) });
        var pieces = machineAccess.Split('.');
        Check(publicKey.VerifyData(Encoding.ASCII.GetBytes(pieces[0] + "." + pieces[1]), Decode(pieces[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), "machine JWT signature validates against JWKS");
    }
    var machineInfo = await Userinfo(machineAccess);
    Check(machineInfo.StatusCode == HttpStatusCode.Forbidden && (await Json(machineInfo)).GetProperty("error").GetString() == "insufficient_scope"
        && machineInfo.Headers.WwwAuthenticate.ToString().Contains("insufficient_scope"), "userinfo rejects valid machine token with insufficient_scope");
    using (var basicRequest = new HttpRequestMessage(HttpMethod.Post, "/token"))
    {
        basicRequest.Headers.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test-secret")));
        basicRequest.Content = new FormUrlEncodedContent(new Dictionary<string,string> { ["grant_type"] = "client_credentials", ["scope"] = "api.read api.read" });
        var basicTokens = await Json(await http.SendAsync(basicRequest));
        Check(basicTokens.GetProperty("scope").GetString() == "api.read", "client credentials Basic authentication succeeds and deduplicates scopes");
    }
    Check((await Json(await Post("/token", MachineFields(null)))).GetProperty("scope").GetString() == "", "omitted machine scope grants no scopes");
    Check((await Json(await Post("/token", MachineFields("")))).GetProperty("scope").GetString() == "", "empty machine scope grants no scopes");
    Check((await Post("/token", MachineFields(secret: "wrong"))).StatusCode == HttpStatusCode.Unauthorized, "machine grant rejects wrong secret");
    var missingSecret = MachineFields(); missingSecret.Remove("client_secret");
    Check((await Post("/token", missingSecret)).StatusCode == HttpStatusCode.Unauthorized, "machine grant rejects missing secret");
    Check((await Post("/token", MachineFields(client: "unknown"))).StatusCode == HttpStatusCode.Unauthorized, "machine grant rejects unknown client");
    foreach (var scope in new[] { "openid", "profile", "email", "offline_access" })
        Check((await Json(await Post("/token", MachineFields(scope)))).GetProperty("error").GetString() == "invalid_scope", "machine grant rejects user scope " + scope);
    // Exercise discovery, PKCE, form_post, nonce, signing keys, and callback validation
    // using the actual ASP.NET Core OIDC handler rather than reproducing its checks.
    async Task RunOidc(string? customIssuer = null)
    {
        var oidcBuilder = WebApplication.CreateBuilder();
        oidcBuilder.Logging.ClearProviders();
        oidcBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        oidcBuilder.Services.AddAuthentication(o =>
        {
            o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        }).AddCookie().AddOpenIdConnect(o =>
        {
            o.Authority = customIssuer ?? baseUrl; o.RequireHttpsMetadata = false;
            if (customIssuer is not null) o.MetadataAddress = baseUrl + "/.well-known/openid-configuration?client_id=test-client";
            o.ClientId = "test-client"; o.ClientSecret = "test-secret";
            o.ResponseType = "code"; o.UsePkce = true; o.SaveTokens = true;
            o.Scope.Add("email"); o.GetClaimsFromUserInfoEndpoint = true;
            o.CorrelationCookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.None;
            o.NonceCookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.None;
        });
        await using var oidcApp = oidcBuilder.Build();
        oidcApp.UseAuthentication();
        oidcApp.MapGet("/login", async (Microsoft.AspNetCore.Http.HttpContext context) =>
            await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = "/done" }));
        oidcApp.MapGet("/done", (Microsoft.AspNetCore.Http.HttpContext context) => context.User.Identity?.IsAuthenticated == true ? "authenticated" : "anonymous");
        await oidcApp.StartAsync();
        var oidcUrl = oidcApp.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single().Replace("127.0.0.1", "localhost");
        var challengeResponse = await http.GetAsync(oidcUrl + "/login");
        var oidcLogin = await http.GetStringAsync(QueryHelpers.AddQueryString(challengeResponse.Headers.Location!.ToString(), "prompt", "login"));
        var callbackResponse = await Post("/oauth/v2/authorize", new()
        {
            ["transactionId"] = Field(oidcLogin, "transactionId"), ["__RequestVerificationToken"] = Field(oidcLogin, "__RequestVerificationToken"),
            ["email"] = "oidc@example.com", ["country"] = "PH", ["language"] = "en", ["scopes"] = "openid profile email", ["decision"] = "allow"
        });
        var callbackHtml = await callbackResponse.Content.ReadAsStringAsync();
        var callbackTarget = WebUtility.HtmlDecode(Regex.Match(callbackHtml, "action=\"([^\"]*)\"").Groups[1].Value);
        var validated = await http.PostAsync(callbackTarget, new FormUrlEncodedContent(new Dictionary<string,string>
        { ["code"] = Field(callbackHtml, "code"), ["state"] = Field(callbackHtml, "state") }));
        Check(validated.StatusCode == HttpStatusCode.Redirect, (customIssuer is null ? "standard" : "custom-issuer") + " ASP.NET Core OIDC callback validates tokens and nonce");
        Check(await http.GetStringAsync(oidcUrl + "/done") == "authenticated", (customIssuer is null ? "standard" : "custom-issuer") + " OIDC client signs in successfully");
        await oidcApp.StopAsync();
    }
    await RunOidc();
    var rotated = await Json(await Post("/token", new() { ["grant_type"] = "refresh_token", ["client_id"] = "test-client", ["client_secret"] = "test-secret", ["refresh_token"] = refresh }));
    var refresh2 = rotated.GetProperty("refresh_token").GetString()!;
    Check(refresh2 != refresh, "refresh token rotates");
    var reuse = await Json(await Post("/token", new() { ["grant_type"] = "refresh_token", ["client_id"] = "test-client", ["client_secret"] = "test-secret", ["refresh_token"] = refresh }));
    Check(reuse.GetProperty("error").GetString() == "invalid_grant", "refresh reuse rejected");
    var family = await Json(await Post("/token", new() { ["grant_type"] = "refresh_token", ["client_id"] = "test-client", ["client_secret"] = "test-secret", ["refresh_token"] = refresh2 }));
    Check(family.GetProperty("error").GetString() == "invalid_grant", "refresh reuse invalidates rotated family");
    var formPost = await Login(mode: "form_post");
    Check(formPost.Response.IsSuccessStatusCode && formPost.Code.Length > 0, "OIDC form_post renders callback form");
    var settings = JsonDocument.Parse(File.ReadAllText(Path.Combine(settingsDirectory, "settings.json"))).RootElement;
    var internalId = settings.GetProperty("clients")[0].GetProperty("id").GetString()!;
    var savedKey = settings.GetProperty("signingPrivateKey").GetString();
    Check(settings.GetProperty("clients")[0].GetProperty("lastLogin").GetProperty("language").GetString() == "fil", "successful login preferences persisted");
    const string customIssuer = "https://identity.example.com/tenant/";
    const string customAudience = "orders-api";
    var clientMetadataUrl = "/.well-known/openid-configuration?client_id=test-client";
    async Task SaveTokenIdentity(string? issuer = null, string? audience = null, bool? requireBasic = null)
    {
        var fields = new Dictionary<string, string>
        {
            ["id"] = internalId, ["clientId"] = "test-client", ["clientSecret"] = "test-secret", ["enabled"] = "true"
        };
        if (issuer is not null) fields["issuer"] = issuer;
        if (audience is not null) fields["accessTokenAudience"] = audience;
        if (requireBasic.HasValue) fields["requireIntrospectionBasicAuthentication"] = requireBasic.Value.ToString();
        Check((await Post("/Admin/SaveClient", fields, true)).StatusCode == HttpStatusCode.Redirect, "admin saves token identity settings");
    }
    Check((await Json(await http.GetAsync(clientMetadataUrl))).GetProperty("issuer").GetString() == baseUrl,
        "unset client issuer uses canonical discovery issuer");
    foreach (var selector in new[] { "client_id=unknown", "client_id=", "client_id=test-client&client_id=test-client" })
        Check((await http.GetAsync("/.well-known/openid-configuration?" + selector)).StatusCode == HttpStatusCode.BadRequest,
            "discovery rejects invalid client selection: " + selector);
    foreach (var invalidIssuer in new[] { "relative", "ftp://identity.example.com", "https://user@identity.example.com", "https://identity.example.com?x=1", "https://identity.example.com#x" })
    {
        var invalidUpdate = await Post("/Admin/SaveClient", new() { ["id"] = internalId, ["clientId"] = "test-client", ["issuer"] = invalidIssuer }, true);
        Check(invalidUpdate.StatusCode == HttpStatusCode.UnprocessableEntity, "admin rejects invalid issuer: " + invalidIssuer);
    }
    Check((await Json(await Introspect(access))).GetProperty("active").GetBoolean(), "invalid issuer edits do not modify token expectations");

    await SaveTokenIdentity(" " + customIssuer + " ", "");
    var issuerOnly = await Json(await Post("/token", MachineFields()));
    Check(Payload(issuerOnly.GetProperty("access_token").GetString()!).GetProperty("iss").GetString() == customIssuer
        && Payload(issuerOnly.GetProperty("access_token").GetString()!).GetProperty("aud").GetString() == "test-client", "issuer override preserves audience fallback and exact trailing slash");
    await SaveTokenIdentity("", " " + customAudience + " ");
    var audienceOnlyLogin = await Login();
    var audienceOnly = await Json(await Post("/token", ExchangeFields(audienceOnlyLogin.Code)));
    Check(Payload(audienceOnly.GetProperty("access_token").GetString()!).GetProperty("iss").GetString() == baseUrl
        && Payload(audienceOnly.GetProperty("access_token").GetString()!).GetProperty("aud").GetString() == customAudience
        && Payload(audienceOnly.GetProperty("id_token").GetString()!).GetProperty("aud").GetString() == "test-client", "audience-only override changes access tokens but not ID tokens");

    await SaveTokenIdentity(customIssuer, customAudience, false);
    var identityLogin = await Login();
    var identityTokens = await Json(await Post("/token", ExchangeFields(identityLogin.Code)));
    var identityAccess = identityTokens.GetProperty("access_token").GetString()!;
    var identityId = Payload(identityTokens.GetProperty("id_token").GetString()!);
    var identityMachine = (await Json(await Post("/token", MachineFields()))).GetProperty("access_token").GetString()!;
    Check(Payload(identityAccess).GetProperty("iss").GetString() == customIssuer && Payload(identityAccess).GetProperty("aud").GetString() == customAudience
        && identityId.GetProperty("iss").GetString() == customIssuer && identityId.GetProperty("aud").GetString() == "test-client", "authorization-code tokens use custom issuer with separate access/ID audiences");
    Check(Payload(identityMachine).GetProperty("iss").GetString() == customIssuer && Payload(identityMachine).GetProperty("aud").GetString() == customAudience
        && Payload(identityMachine).GetProperty("client_id").GetString() == "test-client", "machine tokens keep client identity distinct from API audience");
    Check((await Userinfo(identityAccess)).StatusCode == HttpStatusCode.OK, "userinfo validates custom token identity");
    foreach (var path in new[] { "/introspect", "/oauth/v2/introspect" })
    {
        var inspectedIdentity = await Json(await Introspect(identityAccess, path: path));
        Check(inspectedIdentity.GetProperty("active").GetBoolean() && inspectedIdentity.GetProperty("iss").GetString() == customIssuer
            && inspectedIdentity.GetProperty("aud").GetString() == customAudience, "Basic introspection validates custom issuer/audience: " + path);
        Check((await Json(await AnonymousIntrospect(identityMachine, path))).GetProperty("active").GetBoolean(), "anonymous introspection resolves client independently of custom audience: " + path);
    }
    foreach (var field in new[] { "iss", "aud" })
    {
        var wrongIdentity = System.Text.Json.Nodes.JsonNode.Parse(Payload(identityAccess).GetRawText())!;
        wrongIdentity[field] = field == "iss" ? baseUrl : "test-client";
        var wrongToken = SignInspectionToken(wrongIdentity.ToJsonString());
        Check((await Userinfo(wrongToken)).StatusCode == HttpStatusCode.Unauthorized
            && (await Json(await Introspect(wrongToken))).GetRawText() == "{\"active\":false}"
            && (await Json(await AnonymousIntrospect(wrongToken))).GetRawText() == "{\"active\":false}", "custom identity validation rejects wrong " + field);
    }
    var identityMetadata = await Json(await http.GetAsync(clientMetadataUrl));
    Check(identityMetadata.GetProperty("issuer").GetString() == customIssuer
        && new[] { "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "introspection_endpoint", "jwks_uri" }
            .All(endpoint => identityMetadata.GetProperty(endpoint).GetString()!.StartsWith(baseUrl + "/", StringComparison.Ordinal)),
        "client-specific discovery publishes custom issuer with local endpoints and keys");
    Check((await Json(await http.GetAsync("/.well-known/openid-configuration"))).GetProperty("issuer").GetString() == baseUrl,
        "default discovery remains canonical with a custom client issuer");
    await SaveTokenIdentity();
    Check((await Json(await Introspect(identityAccess))).GetProperty("active").GetBoolean(), "omitted identity form fields preserve overrides");
    await RunOidc(customIssuer);

    await SaveTokenIdentity("https://identity.example.com/changed", "new-api");
    Check((await Userinfo(identityAccess)).StatusCode == HttpStatusCode.Unauthorized
        && (await Json(await Introspect(identityMachine))).GetRawText() == "{\"active\":false}", "identity edits immediately reject old token expectations");
    var identityRefreshed = await Json(await Post("/token", new()
    {
        ["grant_type"] = "refresh_token", ["client_id"] = "test-client", ["client_secret"] = "test-secret",
        ["refresh_token"] = identityTokens.GetProperty("refresh_token").GetString()!
    }));
    Check(Payload(identityRefreshed.GetProperty("access_token").GetString()!).GetProperty("iss").GetString() == "https://identity.example.com/changed"
        && Payload(identityRefreshed.GetProperty("access_token").GetString()!).GetProperty("aud").GetString() == "new-api"
        && Payload(identityRefreshed.GetProperty("id_token").GetString()!).GetProperty("aud").GetString() == "test-client"
        && (await Json(await Introspect(identityRefreshed.GetProperty("access_token").GetString()!))).GetProperty("active").GetBoolean(), "refresh uses current issuer/audience while retaining ID-token audience");
    await SaveTokenIdentity(customIssuer, customAudience);
    Stop(); server = Start(); await Ready();
    Check((await Json(await http.GetAsync(clientMetadataUrl))).GetProperty("issuer").GetString() == customIssuer
        && (await Json(await AnonymousIntrospect(identityMachine))).GetProperty("aud").GetString() == customAudience,
        "issuer and audience overrides persist across restart with access-token validity");

    Check((await Post("/Admin/SaveClient", new()
    {
        ["clientId"] = "identity-other", ["clientSecret"] = "other-secret", ["enabled"] = "true",
        ["issuer"] = "https://other.example.com/", ["accessTokenAudience"] = customAudience
    }, true)).StatusCode == HttpStatusCode.Redirect, "admin creates another client sharing the API audience");
    var otherMachine = (await Json(await Post("/token", MachineFields(client: "identity-other", secret: "other-secret")))).GetProperty("access_token").GetString()!;
    Check((await Json(await Introspect(otherMachine))).GetRawText() == "{\"active\":false}"
        && (await AnonymousIntrospect(otherMachine)).StatusCode == HttpStatusCode.Unauthorized,
        "shared API audience does not bypass introspection ownership or select another client's OFF policy");
    var wrongClientIssuer = System.Text.Json.Nodes.JsonNode.Parse(Payload(identityAccess).GetRawText())!;
    wrongClientIssuer["iss"] = "https://other.example.com/";
    Check((await Json(await Introspect(SignInspectionToken(wrongClientIssuer.ToJsonString())))).GetRawText() == "{\"active\":false}",
        "validation does not accept another client's issuer for a shared audience");
    var otherInternalId = JsonDocument.Parse(File.ReadAllText(Path.Combine(settingsDirectory, "settings.json"))).RootElement.GetProperty("clients")[1].GetProperty("id").GetString()!;
    Check((await Post("/Admin/SaveClient", new() { ["id"] = otherInternalId, ["clientId"] = "identity-other", ["clientSecret"] = "other-secret", ["enabled"] = "false" }, true)).StatusCode == HttpStatusCode.Redirect
        && (await http.GetAsync("/.well-known/openid-configuration?client_id=identity-other")).StatusCode == HttpStatusCode.BadRequest,
        "client-specific discovery rejects disabled clients");
    Check((await Post("/Admin/DeleteClient", new() { ["id"] = otherInternalId }, true)).StatusCode == HttpStatusCode.Redirect, "temporary identity client deleted");
    await SaveTokenIdentity(" \t ", " \t ", true);
    Check((await Json(await http.GetAsync(clientMetadataUrl))).GetProperty("issuer").GetString() == baseUrl
        && (await Json(await Introspect(access))).GetProperty("active").GetBoolean()
        && (await Json(await Introspect(identityAccess))).GetRawText() == "{\"active\":false}", "clearing overrides restores default expectations immediately");
    var addPublic = await Post("/Admin/SaveClient", new() { ["clientId"] = "public-client", ["name"] = "Public", ["isPublic"] = "true", ["enabled"] = "true" }, true);
    Check(addPublic.StatusCode == HttpStatusCode.Redirect, "admin creates public client");
    Check((await Introspect(access, "public-client", "")).StatusCode == HttpStatusCode.Unauthorized, "public clients cannot introspect");
    Check((await http.GetStringAsync("/")).Contains("Introspection requires confidential-client authentication"), "public client admin provides JWT validation guidance");
    var publicMachine = MachineFields(client: "public-client"); publicMachine.Remove("client_secret");
    var publicRejected = await Post("/token", publicMachine);
    Check(publicRejected.StatusCode == HttpStatusCode.BadRequest && (await Json(publicRejected)).GetProperty("error").GetString() == "unauthorized_client", "public clients cannot use client credentials");
    var noPkce = await http.GetAsync(QueryHelpers.AddQueryString("/authorize", new Dictionary<string, string?> { ["client_id"] = "public-client", ["redirect_uri"] = callback, ["response_type"] = "code" }));
    Check(noPkce.Headers.Location?.Query.Contains("invalid_request") == true, "public client requires PKCE");
    var pkce = await Login("public-client", scope: "openid profile email", pkce: challenge);
    var pkceFields = ExchangeFields(pkce.Code, "public-client", "", verifier);
    pkceFields.Remove("client_secret");
    Check((await Post("/token", pkceFields)).IsSuccessStatusCode, "public client S256 exchange succeeds");
    var cookiePkceUrl = QueryHelpers.AddQueryString("/authorize", new Dictionary<string, string?>
    {
        ["response_type"] = "code", ["client_id"] = "public-client", ["redirect_uri"] = callback, ["scope"] = "openid email",
        ["state"] = "reused-state", ["nonce"] = "reused-nonce", ["code_challenge"] = challenge, ["code_challenge_method"] = "S256"
    });
    var cookiePkceHtml = await http.GetStringAsync(cookiePkceUrl);
    var cookiePkceComplete = await Post("/oauth/v2/continue", new()
    { ["transactionId"] = Field(cookiePkceHtml, "transactionId"), ["__RequestVerificationToken"] = Field(cookiePkceHtml, "__RequestVerificationToken") });
    var cookieQuery = QueryHelpers.ParseQuery(cookiePkceComplete.Headers.Location!.Query);
    Check(cookieQuery["state"] == "reused-state", "session reuse preserves request state");
    var cookiePkceFields = ExchangeFields(cookieQuery["code"].ToString(), "public-client", "", verifier); cookiePkceFields.Remove("client_secret");
    var cookieTokens = await Json(await Post("/token", cookiePkceFields));
    Check((await Json(await Introspect(cookieTokens.GetProperty("access_token").GetString()!))).GetRawText() == "{\"active\":false}", "introspection does not disclose another client's token claims");
    var publicAccess = cookieTokens.GetProperty("access_token").GetString()!;
    Check((await AnonymousIntrospect(publicAccess)).StatusCode == HttpStatusCode.Unauthorized, "public client's ON switch rejects anonymous introspection");
    settings = JsonDocument.Parse(File.ReadAllText(Path.Combine(settingsDirectory, "settings.json"))).RootElement;
    var publicInternalId = settings.GetProperty("clients")[1].GetProperty("id").GetString()!;
    async Task SavePublicIntrospection(bool requireBasic)
    {
        // The checkbox and hidden fallback submit true,false when checked.
        var fields = new List<KeyValuePair<string, string>>
        {
            new("id", publicInternalId), new("clientId", "public-client"), new("name", "Public"), new("isPublic", "true"), new("enabled", "true"),
            new("__RequestVerificationToken", Field(await http.GetStringAsync("/"), "__RequestVerificationToken"))
        };
        if (requireBasic) fields.Add(new("requireIntrospectionBasicAuthentication", "true"));
        fields.Add(new("requireIntrospectionBasicAuthentication", "false"));
        Check((await http.PostAsync("/Admin/SaveClient", new FormUrlEncodedContent(fields))).StatusCode == HttpStatusCode.Redirect, "admin saves introspection checkbox with hidden fallback");
    }
    await SavePublicIntrospection(false);
    foreach (var path in new[] { "/introspect", "/oauth/v2/introspect" })
    {
        var anonymous = await AnonymousIntrospect(publicAccess, path);
        var claims = await Json(anonymous);
        Check(anonymous.StatusCode == HttpStatusCode.OK && claims.GetProperty("active").GetBoolean()
            && claims.GetProperty("client_id").GetString() == "public-client", "OFF switch infers public client from validated token: " + path);
        Check(anonymous.Headers.CacheControl?.NoStore == true && anonymous.Headers.Pragma.Any(p => p.Name == "no-cache"), "anonymous introspection is non-cacheable");
    }
    Check((await http.GetStringAsync("/")).Contains("no credentials required"), "admin integration reflects OFF mode");
    Check((await AnonymousIntrospect(access, claimedClient: "public-client")).StatusCode == HttpStatusCode.Unauthorized, "anonymous client_id cannot select another client's OFF policy");
    Check((await Introspect(publicAccess, secret: "wrong")).StatusCode == HttpStatusCode.Unauthorized, "invalid supplied Basic cannot fall back to OFF anonymous mode");
    Check((await Json(await Introspect(publicAccess))).GetRawText() == "{\"active\":false}", "valid Basic still enforces token ownership when token owner's switch is OFF");
    await SavePublicIntrospection(true);
    Check((await AnonymousIntrospect(publicAccess)).StatusCode == HttpStatusCode.Unauthorized, "turning switch back ON takes effect immediately");
    await SavePublicIntrospection(false);
    Check(Payload(cookieTokens.GetProperty("id_token").GetString()!).GetProperty("nonce").GetString() == "reused-nonce", "session reuse preserves PKCE and nonce");
    var cookieGrantAuthTime = Payload(cookieTokens.GetProperty("id_token").GetString()!).GetProperty("auth_time").GetInt64();
    await Task.Delay(1100);
    var silent = await http.GetAsync(QueryHelpers.AddQueryString(cookiePkceUrl, "prompt", "none"));
    var silentFields = ExchangeFields(QueryHelpers.ParseQuery(silent.Headers.Location!.Query)["code"].ToString(), "public-client", "", verifier); silentFields.Remove("client_secret");
    var silentTokens = await Json(await Post("/token", silentFields));
    Check(Payload(silentTokens.GetProperty("id_token").GetString()!).GetProperty("auth_time").GetInt64() == cookieGrantAuthTime, "silent session reuse retains original authentication time");
    var badPkce = await Login("public-client", scope: "openid", pkce: challenge);
    var badFields = ExchangeFields(badPkce.Code, "public-client", "", new string('x', 43)); badFields.Remove("client_secret");
    Check((await Json(await Post("/token", badFields))).GetProperty("error").GetString() == "invalid_grant", "wrong PKCE verifier rejected");
    Check((await Post("/Admin/SaveUser", new()
    {
        ["client"] = internalId, ["email"] = "configured@example.com", ["name"] = "Configured user", ["country"] = "PH", ["language"] = "en", ["enabled"] = "true", ["claims"] = "{\"roles\":{\"role\":\"tester\",\"iss\":\"override\"}}"
    }, true)).StatusCode == HttpStatusCode.Redirect, "admin creates configured user with scoped claims");
    settings = JsonDocument.Parse(File.ReadAllText(Path.Combine(settingsDirectory, "settings.json"))).RootElement;
    var userId = settings.GetProperty("clients")[0].GetProperty("users")[0].GetProperty("id").GetString();
    var configured = await Login(user: userId, scope: "openid profile email roles");
    var customToken = await Json(await Post("/token", ExchangeFields(configured.Code)));
    var customProfile = await Json(await Userinfo(customToken.GetProperty("access_token").GetString()!));
    Check(customProfile.GetProperty("role").GetString() == "tester" && customProfile.GetProperty("email").GetString() == "configured@example.com", "configured user and scoped custom claims emitted");
    Check((await Json(await Introspect(customToken.GetProperty("access_token").GetString()!))).GetProperty("role").GetString() == "tester", "introspection includes scoped configured-user claims");
    Check((await Post("/Admin/SaveClient", new()
    {
        ["id"] = internalId, ["clientId"] = "test-client", ["clientSecret"] = "test-secret", ["enabled"] = "true", ["redirectUris"] = callback, ["scopes"] = "openid profile email roles"
    }, true)).StatusCode == HttpStatusCode.Redirect, "admin configures strict redirect/scope lists");
    var invalidRedirect = await http.GetAsync("/authorize?client_id=test-client&redirect_uri=http://localhost:9999/bad&response_type=code");
    Check(invalidRedirect.StatusCode == HttpStatusCode.BadRequest && invalidRedirect.Headers.Location is null, "invalid redirect displays local error without redirecting");
    var invalidScope = await http.GetAsync(QueryHelpers.AddQueryString("/authorize", new Dictionary<string, string?> { ["client_id"] = "test-client", ["redirect_uri"] = callback, ["response_type"] = "code", ["scope"] = "forbidden" }));
    Check(invalidScope.Headers.Location?.Query.Contains("invalid_scope") == true, "configured scope list enforced");
    async Task SaveMachineClient(string scopes, bool relaxed = false, bool enabled = true, string? claims = null, bool requireBasic = true, string secret = "test-secret")
    {
        var fields = new Dictionary<string, string>
        {
            ["id"] = internalId, ["clientId"] = "test-client", ["clientSecret"] = secret, ["enabled"] = enabled.ToString(),
            ["redirectUris"] = callback, ["scopes"] = scopes, ["relaxScopes"] = relaxed.ToString(), ["requireIntrospectionBasicAuthentication"] = requireBasic.ToString()
        };
        if (claims is not null) fields["claims"] = claims;
        Check((await Post("/Admin/SaveClient", fields, true)).StatusCode == HttpStatusCode.Redirect, "machine client settings saved");
    }
    const string machineClaims = "{\"api.read\":{\"role\":\"service\",\"tenant\":\"sandbox\",\"sub\":\"forged\",\"iss\":\"forged\",\"grant_type\":\"authorization_code\",\"email\":\"forged@example.com\",\"active\":false,\"token_type\":\"forged\",\"limit\":3,\"features\":[\"read\"],\"context\":{\"sandbox\":true}},\"api.write\":{\"write_permission\":true}}";
    await SaveMachineClient("openid profile email roles api.read api.write", claims: machineClaims);
    var claimsDashboard = await http.GetStringAsync("/");
    using (var savedClaims = JsonDocument.Parse(Field(claimsDashboard, "claims")))
        Check(savedClaims.RootElement.GetProperty("api.read").GetProperty("context").GetProperty("sandbox").GetBoolean()
            && savedClaims.RootElement.GetProperty("api.read").GetProperty("limit").GetInt32() == 3,
            "application editor reloads saved typed claims in its compatible form payload");
    var scopedMachine = await Json(await Post("/token", MachineFields()));
    var scopedPayload = Payload(scopedMachine.GetProperty("access_token").GetString()!);
    var scopedInspection = await Json(await Introspect(scopedMachine.GetProperty("access_token").GetString()!));
    Check(scopedInspection.GetProperty("active").GetBoolean() && scopedInspection.GetProperty("token_type").GetString() == "Bearer"
        && scopedInspection.GetProperty("limit").GetInt32() == 3 && scopedInspection.GetProperty("features")[0].GetString() == "read"
        && scopedInspection.GetProperty("context").GetProperty("sandbox").GetBoolean() && !scopedInspection.TryGetProperty("write_permission", out _), "introspection preserves custom JSON types and overrides forged metadata");
    var scopedMachineAccess = scopedMachine.GetProperty("access_token").GetString()!;
    await SaveMachineClient("openid profile email roles api.read api.write", requireBasic: false);
    Check((await Json(await AnonymousIntrospect(scopedMachineAccess))).GetProperty("context").GetProperty("sandbox").GetBoolean(), "anonymous machine introspection preserves custom JSON claims");
    Check((await Json(await AnonymousIntrospect(access))).GetProperty("email").GetString() == "person@example.com", "confidential OFF switch supports user access tokens");
    Check((await Introspect(scopedMachineAccess, basic: false)).StatusCode == HttpStatusCode.BadRequest, "OFF switch also rejects form client secrets");
    const string changedSecret = "new:secret+é";
    await SaveMachineClient("openid profile email roles api.read api.write", secret: changedSecret);
    Check((await Introspect(scopedMachineAccess)).StatusCode == HttpStatusCode.Unauthorized, "admin secret change immediately rejects old Basic credentials");
    Check((await Json(await Introspect(scopedMachineAccess, secret: changedSecret))).GetProperty("active").GetBoolean(), "Basic authentication accepts updated URL-encoded credentials with reserved and Unicode characters");
    await SaveMachineClient("openid profile email roles api.read api.write");
    Check(scopedPayload.GetProperty("role").GetString() == "service" && scopedPayload.GetProperty("tenant").GetString() == "sandbox"
        && !scopedPayload.TryGetProperty("write_permission", out _), "machine custom claims are limited to granted scopes");
    Check(scopedPayload.GetProperty("sub").GetString() == "test-client" && scopedPayload.GetProperty("iss").GetString() == baseUrl
        && scopedPayload.GetProperty("grant_type").GetString() == "client_credentials" && !scopedPayload.TryGetProperty("email", out _), "machine claims cannot override reserved identity or token fields");
    Check((await Json(await Post("/token", MachineFields("unregistered")))).GetProperty("error").GetString() == "invalid_scope", "configured scope list enforced for machine tokens");
    var noScopePayload = Payload((await Json(await Post("/token", MachineFields(null)))).GetProperty("access_token").GetString()!);
    Check(!noScopePayload.TryGetProperty("role", out _), "omitted scope does not implicitly grant configured scopes or claims");
    var invalidClaims = await Post("/Admin/SaveClient", new()
    {
        ["id"] = internalId, ["clientId"] = "test-client", ["enabled"] = "true", ["claims"] = "{\"api.read\":null}"
    }, true);
    Check(invalidClaims.StatusCode == HttpStatusCode.UnprocessableEntity, "admin rejects invalid application claim JSON without changing settings");
    await SaveMachineClient("openid profile email roles api.read api.write", relaxed: true);
    Check((await Post("/token", MachineFields("unregistered"))).IsSuccessStatusCode, "relaxed scope policy allows extra machine scopes");
    Check((await Json(await Post("/token", MachineFields("openid")))).GetProperty("error").GetString() == "invalid_scope", "relaxed policy still rejects machine user scopes");
    await SaveMachineClient("openid profile email roles api.read api.write", enabled: false);
    Check((await Post("/token", MachineFields())).StatusCode == HttpStatusCode.Unauthorized, "machine grant rejects disabled client");
    Check((await Introspect(access)).StatusCode == HttpStatusCode.Unauthorized, "disabled clients cannot introspect");
    Check((await Json(await AnonymousIntrospect(access))).GetRawText() == "{\"active\":false}", "disabled client's token is inactive for anonymous inspection");
    await SaveMachineClient("openid profile email roles api.read api.write");
    var preservedMachine = Payload((await Json(await Post("/token", MachineFields()))).GetProperty("access_token").GetString()!);
    Check(preservedMachine.GetProperty("role").GetString() == "service", "editing client without application claims field preserves saved claims");
    using (var corsRequest = new HttpRequestMessage(HttpMethod.Options, "/token"))
    {
        corsRequest.Headers.Add("Origin", "http://localhost:3000");
        var cors = await http.SendAsync(corsRequest);
        Check(cors.StatusCode == HttpStatusCode.NoContent && cors.Headers.Contains("Access-Control-Allow-Origin"), "loopback SPA CORS preflight succeeds");
    }
    var pending = await Login("public-client", scope: "openid offline_access", pkce: challenge);
    var pendingFields = ExchangeFields(pending.Code, "public-client", "", verifier); pendingFields.Remove("client_secret");
    var pendingTokens = await Json(await Post("/token", pendingFields));
    Stop();
    output.Clear();
    server = Start();
    await Ready();
    settings = JsonDocument.Parse(File.ReadAllText(Path.Combine(settingsDirectory, "settings.json"))).RootElement;
    Check(settings.GetProperty("signingPrivateKey").GetString() == savedKey, "signing key survives server restart");
    Check(settings.GetProperty("clients").GetArrayLength() == 2 && settings.GetProperty("clients")[0].GetProperty("users").GetArrayLength() == 1, "clients and users survive server restart");
    Check(settings.GetProperty("clients")[0].GetProperty("requireIntrospectionBasicAuthentication").GetBoolean()
        && !settings.GetProperty("clients")[1].GetProperty("requireIntrospectionBasicAuthentication").GetBoolean(), "per-client introspection switches survive restart independently");
    Check((await Json(await AnonymousIntrospect(publicAccess))).GetProperty("active").GetBoolean(), "OFF client permits anonymous introspection after restart");
    Check((await AnonymousIntrospect(access)).StatusCode == HttpStatusCode.Unauthorized, "ON client still requires Basic after restart");
    Check(!output.ToString().Contains("Secret:") && !output.ToString().Contains("Client ID:"), "multiple-client startup suppresses credentials");
    var lostRefresh = await Json(await Post("/token", new() { ["grant_type"] = "refresh_token", ["client_id"] = "public-client", ["refresh_token"] = pendingTokens.GetProperty("refresh_token").GetString()! }));
    Check(lostRefresh.GetProperty("error").GetString() == "invalid_grant", "refresh tokens invalid after restart");
    Check((await Userinfo(access)).IsSuccessStatusCode, "signed access token still valid after same-issuer restart");
    Check((await Json(await Introspect(access))).GetProperty("active").GetBoolean(), "introspection preserves access-token validity after restart");
    Check(settings.GetProperty("clients")[0].GetProperty("claimsByScope").GetProperty("api.read").GetProperty("role").GetString() == "service", "application claims survive restart");
    var restartedMachine = Payload((await Json(await Post("/token", MachineFields()))).GetProperty("access_token").GetString()!);
    Check(restartedMachine.GetProperty("role").GetString() == "service", "machine grant emits persisted claims after restart");
    var resetLogin = await Login("public-client", scope: "openid offline_access", pkce: challenge);
    var resetFields = ExchangeFields(resetLogin.Code, "public-client", "", verifier); resetFields.Remove("client_secret");
    var resetTokens = await Json(await Post("/token", resetFields));
    var unredeemed = await Login("public-client", scope: "openid", pkce: challenge);
    var resumeUrl = QueryHelpers.AddQueryString("/authorize", new Dictionary<string, string?>
    {
        ["response_type"] = "code", ["client_id"] = "public-client", ["redirect_uri"] = callback, ["scope"] = "openid",
        ["code_challenge"] = challenge, ["code_challenge_method"] = "S256"
    });
    var welcome = await http.GetStringAsync(resumeUrl);
    Check(welcome.Contains("Welcome back, person!"), "valid per-client cookie skips login");
    var beforeResetJwks = await Json(await http.GetAsync("/oauth/v2/jwks"));
    Check((await Post("/Admin/InvalidateAll", new())).StatusCode == HttpStatusCode.BadRequest, "global reset requires antiforgery token");
    Check((await Post("/Admin/InvalidateAll", new(), true)).StatusCode == HttpStatusCode.Redirect, "admin global reset succeeds");
    Check((await Userinfo(access)).StatusCode == HttpStatusCode.Unauthorized, "admin reset rejects old access JWT");
    Check((await Userinfo(machineAccess)).StatusCode == HttpStatusCode.Unauthorized, "admin reset rejects old machine JWT");
    foreach (var old in new[] { access, machineAccess })
    {
        Check((await Json(await Introspect(old))).GetRawText() == "{\"active\":false}", "introspection reports reset-invalidated tokens inactive");
        Check((await Json(await AnonymousIntrospect(old))).GetRawText() == "{\"active\":false}", "anonymous reset-invalidated tokens return inactive");
    }
    var revokedFields = ExchangeFields(unredeemed.Code, "public-client", "", verifier); revokedFields.Remove("client_secret");
    Check((await Json(await Post("/token", revokedFields))).GetProperty("error").GetString() == "invalid_grant", "admin reset clears authorization codes");
    Check((await Json(await Post("/token", new() { ["grant_type"] = "refresh_token", ["client_id"] = "public-client", ["refresh_token"] = resetTokens.GetProperty("refresh_token").GetString()! }))).GetProperty("error").GetString() == "invalid_grant", "admin reset clears refresh families");
    Check((await Post("/oauth/v2/continue", new() { ["transactionId"] = Field(welcome, "transactionId"), ["__RequestVerificationToken"] = Field(welcome, "__RequestVerificationToken") })).StatusCode == HttpStatusCode.BadRequest, "admin reset clears pending welcome requests");
    Check((await http.GetStringAsync(resumeUrl)).Contains("Sign in to"), "admin reset rejects existing browser session cookie");
    var afterResetJwks = await Json(await http.GetAsync("/oauth/v2/jwks"));
    Check(beforeResetJwks.GetProperty("keys")[0].GetProperty("kid").GetString() != afterResetJwks.GetProperty("keys")[0].GetProperty("kid").GetString(), "admin reset publishes rotated JWKS");
    var freshMachine = (await Json(await Post("/token", MachineFields()))).GetProperty("access_token").GetString()!;
    Check((await Json(await Introspect(freshMachine))).GetProperty("active").GetBoolean(), "introspection accepts tokens signed after global reset");
    using (var newRsa = RSA.Create())
    {
        var key = afterResetJwks.GetProperty("keys")[0];
        newRsa.ImportParameters(new RSAParameters { Modulus = WebEncoders.Base64UrlDecode(key.GetProperty("n").GetString()!), Exponent = WebEncoders.Base64UrlDecode(key.GetProperty("e").GetString()!) });
        var parts = freshMachine.Split('.');
        Check(newRsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), WebEncoders.Base64UrlDecode(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), "new JWT verifies against rotated JWKS");
        var oldParts = idToken.Split('.');
        Check(!newRsa.VerifyData(Encoding.ASCII.GetBytes(oldParts[0] + "." + oldParts[1]), WebEncoders.Base64UrlDecode(oldParts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), "old ID JWT rejected by rotated key");
    }
    var rotatedKey = JsonDocument.Parse(File.ReadAllText(Path.Combine(settingsDirectory, "settings.json"))).RootElement.GetProperty("signingPrivateKey").GetString();
    Stop(); server = Start(); await Ready();
    Check(JsonDocument.Parse(File.ReadAllText(Path.Combine(settingsDirectory, "settings.json"))).RootElement.GetProperty("signingPrivateKey").GetString() == rotatedKey, "rotated signing key persists after restart");
    using (var busy = Start("--port", port.ToString()))
    {
        await busy.WaitForExitAsync();
        Check(busy.ExitCode != 0, "second instance using same settings fails clearly");
    }
    var busyDirectory = Path.Combine(directory, "busy-port");
    using (var occupied = Start("--settings-dir", busyDirectory, "--port", port.ToString()))
    {
        await occupied.WaitForExitAsync();
        Check(occupied.ExitCode != 0 && !File.Exists(Path.Combine(busyDirectory, "settings.json")), "explicit occupied port fails without persisting startup overrides");
    }
    using (var busyStore = new SettingsStore(busyDirectory))
    {
        busyStore.ApplyStartup(new(port, "busy-test", "busy-secret", true, busyDirectory));
        busyStore.Update(s => s.Port = port);
    }
    using (var fallback = Start("--settings-dir", busyDirectory))
    {
        try
        {
        var ready = false;
        for (var i = 0; i < 300 && !fallback.HasExited; i++)
        {
            await Task.Delay(100);
            try
            {
                var saved = JsonDocument.Parse(File.ReadAllText(Path.Combine(busyDirectory, "settings.json"))).RootElement;
                var actual = saved.GetProperty("port").GetInt32();
                if (actual != port)
                {
                    var response = await http.GetAsync($"http://localhost:{actual}/.well-known/openid-configuration");
                    ready = response.IsSuccessStatusCode;
                    if (ready) break;
                }
            }
            catch (HttpRequestException) { }
            catch (IOException) { } // Atomic settings replacement may briefly hold the file on Windows.
        }
        if (!ready) Console.Error.WriteLine(output.ToString());
        Check(ready, "occupied saved port selects, persists, and serves on an available port");
        }
        finally
        {
            if (!fallback.HasExited) fallback.Kill(true);
            await fallback.WaitForExitAsync();
        }
    }
    Console.WriteLine($"\n{checks} checks passed.");
}
finally
{
    Stop();
    Directory.Delete(directory, true);
}

sealed class TestClock : TimeProvider
{
    public DateTimeOffset Initial { get; } = DateTimeOffset.UtcNow;
    private TimeSpan elapsed;
    public override DateTimeOffset GetUtcNow() => Initial.Add(elapsed);
    public void Advance(TimeSpan amount) => elapsed += amount;
}
