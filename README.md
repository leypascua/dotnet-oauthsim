# OAuthSim

A .NET 10 OAuth 2.0 / OpenID Connect simulator with a responsive browser-based admin page. Run locally as a CLI tool, behind a reverse proxy, or under IIS.

## Install and run

```sh
dotnet pack OAuthSim.slnx -c Release -o artifacts
dotnet tool install --global OAuthSim --add-source ./artifacts
dotnet oauth-sim --port 42069 --clientId "my-client" --clientSecret "my-secret"
```

All three options are optional. CLI values override saved values and become next-launch defaults. First-run port is 42069 and credentials are generated. The server opens the admin page after binding. Add `--no-browser` for headless use, or `--settings-dir <directory>` for an independent configuration (also useful for tests). `--help` lists options.

Requires the .NET 10 SDK / ASP.NET Core runtime. The tool contains compiled pages and has no database, static files, or Node build. HTMX 2.0.11, AlpineJS 3.17.4, Bulma 1.0.4, and the Inter / JetBrains Mono variable fonts (`@fontsource-variable` 5.2.8) load from jsDelivr; interactive styling/features need CDN access. The UI follows the operating system light/dark preference and reduced-motion setting.

### Run from source

From the repository root, specify the application project:

```sh
dotnet run --project src/OAuthSim.Web
```

Pass simulator options after `--`, for example:

```sh
dotnet run --project src/OAuthSim.Web -- --port 42069 --no-browser
```

Plain `dotnet run` works from `src/OAuthSim.Web`; the repository root contains a solution rather than a runnable project.

### HTTPS, custom hostnames, and reverse proxies

Configure the externally visible URL separately from the backend listener:

```sh
dotnet oauth-sim --port 42069 --no-browser \
  --public-base-url https://login.example.com/oauthsim
```

`--public-base-url` is persisted as `publicBaseUrl` in settings. It can also be supplied through `OAUTHSIM_PUBLIC_BASE_URL`; the CLI option takes precedence over the environment, which takes precedence over saved settings. It must be an absolute HTTP(S) URL without credentials, query, or fragment. Trailing slashes are removed. An optional path, such as `/oauthsim`, becomes the application path. Without a public URL, standalone CLI use retains `http://localhost:<port>`.

Discovery, integration examples, and the default access/ID-token issuer use this public URL, independent of the backend address or request headers. Per-client issuer overrides still take precedence for token identity. Changing the public URL invalidates existing access tokens that used the previous default issuer. HTTP aliases remain available beneath the application path.

For HTTPS termination at a proxy, forward `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-For`. The simulator accepts one forwarding hop from loopback by default. For a remote proxy, repeat `--trusted-proxy` for each trusted IP or CIDR network:

```sh
dotnet oauth-sim --no-browser --public-base-url https://login.example.com \
  --trusted-proxy 10.0.0.10 --trusted-proxy 192.0.2.0/24
```

These values replace the loopback defaults and persist as the `trustedProxies` array. `OAUTHSIM_TRUSTED_PROXIES` accepts a comma-separated list; explicit CLI entries take precedence. Forwarded headers from other peers are ignored. The configured public hostname/port and the actual local backend address are accepted; other hosts are rejected. HTTPS forwarding produces secure login and antiforgery cookies, scoped to the application path.

Example nginx location inside an HTTPS virtual host for `login.example.com`:

```nginx
location /oauthsim/ {
    proxy_pass http://127.0.0.1:42069/;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

The proxy may strip the configured prefix (as above) or preserve it. Form actions, HTMX saves, login/logout, navigation, and cookies respect that prefix. IIS can supply it through `PathBase` directly. Configure a single forwarding hop to the simulator; this example overwrites forwarding headers at the proxy.

### IIS and ASP.NET Core managed bindings

`--hosted` uses the hosting platform's bindings instead of forcing the CLI loopback listener. It requires a configured public base URL and cannot be combined with `--port`. Browser auto-launch and occupied-port fallback are disabled in hosted mode. IIS supplies its own server/bindings; standalone Kestrel accepts standard `ASPNETCORE_URLS`, `ASPNETCORE_HTTP_PORTS`, `ASPNETCORE_HTTPS_PORTS`, and `Kestrel:Endpoints` configuration, including HTTPS certificates and multiple listeners. With a public URL configured, these explicit binding settings are also detected automatically when `--port` is absent.

For example, in PowerShell, to expose an HTTP backend to a remote proxy:

```powershell
$env:ASPNETCORE_URLS = 'http://0.0.0.0:8080'
dotnet oauth-sim --hosted --no-browser --public-base-url https://login.example.com --trusted-proxy 10.0.0.10
```

For IIS, install the .NET 10 Hosting Bundle and publish the web application rather than the tool package:

```sh
dotnet publish src/OAuthSim.Web -c Release -p:PackAsTool=false -o artifacts/iis
```

Create an IIS site or application pointing to the published directory, configure its HTTPS hostname binding, and give its application-pool identity Modify access to the chosen settings directory. In the generated `web.config`, set the `aspNetCore` arguments, for example:

```xml
<aspNetCore processPath="dotnet"
            arguments=".\OAuthSim.Web.dll --hosted --no-browser --public-base-url https://login.example.com/oauthsim --settings-dir C:\ProgramData\OAuthSim"
            hostingModel="inprocess" />
```

Use `/oauthsim` in the public URL when deploying as an IIS application at that path; omit it for a site rooted at `/`. Both IIS in-process and out-of-process hosting use platform-managed bindings. Saved settings remain shared by only one running instance, so stop the old instance before recycling into the same settings directory.

## Configuration

Settings live in `~/.oauth-sim/settings.json` (`%USERPROFILE%\.oauth-sim\settings.json` on Windows). Clients, users, signing keys, token lifetimes, and per-client last successful login selections survive restarts. Writes are atomic with a `settings.json.bak` backup. A lock prevents simultaneous writers; use separate settings directories to run multiple servers. A malformed document is preserved and startup fails with recovery instructions.

The admin page shows the server endpoints, token lifetimes and the global reset, then one card per client with Settings, Users and Integration tabs (the active tab is remembered per client for the browser session). It supports public/confidential authentication, redirect URIs, allowed scopes, users, scoped custom JSON claims, copyable client IDs/secrets, and ready-to-use authorization URL and curl examples. Empty redirect/scope lists accept values from the request; configured lists validate exact redirect URIs and allowed scopes unless their relaxed switch is enabled. Unknown/disabled clients are rejected. Startup prints credentials only when one client exists. Explicit busy ports fail; saved/default busy ports fall back to an available port.

## Endpoints

| Endpoint | Behavior |
|---|---|
| `/oauth/v2/authorize` | Authorization code login, query or `form_post` response |
| `/oauth/v2/token` | Code exchange, client credentials, and rotating refresh tokens |
| `/oauth/v2/userinfo` | GET/POST with bearer access token |
| `/oauth/v2/introspect` | POST to validate and inspect access tokens for an authenticated audience (RFC 7662), or anonymously when enabled |
| `/.well-known/openid-configuration` | OIDC discovery |
| `/oauth/v2/jwks` | Public RS256 keys |

`/authorize`, `/token`, `/userinfo`, and `/introspect` are aliases. The default issuer is the configured public base URL, or the printed `http://localhost:<port>` origin for local CLI use. Configure OIDC clients to allow HTTP metadata during local development (ASP.NET Core: `RequireHttpsMetadata = false`). HTTPS deployments use HTTPS metadata normally.

The token endpoint supports `client_secret_basic` and `client_secret_post` for confidential clients. Public clients require S256 PKCE and no secret. Supported grants are `authorization_code`, `refresh_token`, and `client_credentials` (confidential clients only). Request objects and implicit/hybrid flows are not implemented.

### Per-client issuer and audience

Each client's **Settings → Token identity** section has two optional overrides:

| Setting | Configured behavior | Blank/unset behavior |
|---|---|---|
| Issuer override | Sets `iss` in both access and ID tokens | Uses the public base URL, or `http://localhost:<port>` locally |
| Access-token audiences | Sets `aud` in access tokens; one identifier per line | Uses the Client ID |

ID-token `aud` always remains the Client ID. These settings apply to authorization-code, refreshed, and client-credentials tokens, and persist as the client's `issuer` and `accessTokenAudience` properties. Existing settings without these properties retain the defaults. Audience identifiers can be strings such as `orders-api` or API URLs. One audience is persisted and emitted as a string; multiple audiences as an array of strings. Existing single-string settings remain compatible. Audience entries are trimmed, blank entries removed, and duplicates removed using exact case-sensitive comparison. Issuers must be absolute HTTP(S) URLs without credentials, query strings, or fragments. Outer whitespace is trimmed, and issuer paths/trailing slashes are preserved exactly.

Public SPA clients can configure audiences just like confidential clients. For server-side introspection, enter the target server's Client ID, such as `my-server`, in the SPA's **Access-token audiences** field. Enter additional server IDs on separate lines if the same access token targets multiple APIs. Audiences are configured per client; request-time `resource`/`audience` selection is not implemented.

The **Integration** tab shows the effective token identities and a client-specific discovery URL:

```text
http://localhost:42069/.well-known/openid-configuration?client_id=my-client
```

This discovery document publishes that client's effective issuer, while authorization, token, userinfo, introspection, and JWKS endpoints use the server's public base URL (localhost for default CLI use). A per-client issuer override does not change endpoint locations or listener bindings. Discovery without `client_id` publishes the default server issuer; unknown, disabled, blank, or duplicate client selections are rejected.

When using a custom issuer with ASP.NET Core OIDC, configure the local client-specific metadata address explicitly:

```csharp
options.Authority = "https://identity.example.com/tenant/"; // Issuer override
options.MetadataAddress = "http://localhost:42069/.well-known/openid-configuration?client_id=my-client";
options.RequireHttpsMetadata = false; // Local development metadata uses HTTP
options.ClientId = "my-client";
options.ClientSecret = "my-secret";
options.ResponseType = "code";
```

Saving or clearing overrides updates issuance and simulator validation immediately. Existing access tokens whose `iss` or complete `aud` set no longer match the issuing client's current settings become invalid to userinfo/introspection; audience order does not affect validity. Refresh tokens can still issue new tokens using the current settings. OIDC consumers that cache discovery metadata may need to refresh it after issuer changes. The issuing client is determined by signature-validated `client_id`; an authenticated introspection caller is authorized separately by its membership in `aud`. Merely configuring the caller's own tokens with the same audience does not grant introspection access. Reserved `iss`/`aud` entries in custom claims cannot replace these settings.

### Remembered login and logout

A successful login creates an opaque HttpOnly, SameSite=Lax cookie scoped to that client. Its server-side session expires after 15 minutes of inactivity; valid authorization reuse renews both the session and cookie for another 15 minutes. Sessions are in memory and require a fresh login after restart. Disabled/deleted users and disabled clients cannot reuse their sessions; configured user names, emails and scoped claims are resolved from current settings.

A valid session shows **Welcome back, Name!** (configured Name, falling back to the email local part) with the callback host linked and a live five-second countdown. The countdown, destination link and **Continue now** submit the authorization completion form, preserving state, nonce, requested scopes, PKCE and response mode. **Log out** cancels the timer, invalidates that client's session and displays the login form for the same request. Completion and logout require antiforgery-protected POSTs. This local logout is not an OIDC RP-initiated logout endpoint.

`prompt=login`, `consent` and `select_account` display the login form. `prompt=none` completes immediately when a valid session exists, otherwise returns `login_required`. `max_age` limits reuse by the original authentication time; `max_age=0` forces login. Sliding renewal preserves the original OIDC `auth_time`.

The admin **Invalidate all sessions and tokens** action clears all client sessions, pending authorization requests/codes and refresh families, and rotates the persisted RSA key and `kid` without a restart. OAuthSim immediately rejects old JWTs and publishes only the replacement key in JWKS. External applications caching the old public key may continue accepting old JWTs until their key cache refreshes. Login preferences and client/user settings are retained.

Example authorization URL (add `code_challenge` and `code_challenge_method=S256` for PKCE):

```text
http://localhost:42069/oauth/v2/authorize?response_type=code&client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid%20profile%20email%20offline_access&state=random-state&nonce=random-nonce
```

Exchange the returned single-use code:

```sh
curl -u my-client:my-secret http://localhost:42069/oauth/v2/token \
  -d grant_type=authorization_code -d code=RETURNED_CODE \
  --data-urlencode redirect_uri=http://localhost:3000/callback
```

Include `code_verifier` when PKCE was used. Send the returned access token as `Authorization: Bearer <token>` to `/userinfo`.

### Client credentials (application-to-application)

Request an application access token directly, without login, redirect URI, or authorization code:

```sh
curl -u my-client:my-secret http://localhost:42069/oauth/v2/token \
  -d grant_type=client_credentials \
  --data-urlencode "scope=api.read api.write"
```

Alternatively send `client_id` and `client_secret` as form fields. Both `/token` and `/oauth/v2/token` support this flow. The client must be confidential and enabled. Public clients receive `unauthorized_client`; missing or incorrect credentials receive `invalid_client`.

The response contains `access_token`, `token_type: "Bearer"`, `expires_in`, and the granted `scope`. It never contains an ID token or refresh token. The JWT uses the same persisted RS256 key and configured access-token lifetime as user tokens, with the client ID as `sub`, the effective access-token audience as `aud` (Client ID by default), plus `client_id` and `grant_type: "client_credentials"`.

An omitted or empty scope grants no scopes. A configured allowed-scope list is enforced unless relaxed; an empty list accepts requested API scopes. `openid`, `profile`, `email`, and `offline_access` are always rejected with `invalid_scope` for this grant. Application tokens cannot call `/userinfo`, which returns HTTP 403 `insufficient_scope`; use these tokens with your application APIs instead.

In the admin client's **Settings → Application claims** section:

1. Add a scope mapping, such as `api.read`, on the left. Suggestions come from the client's Allowed scopes; adding a mapping does not change that list.
2. Select the scope and add claim rows on the right. Enter a name, choose a value type, and enter the value. For example, use `role`, **String**, and `service` (without JSON quotes).
3. Use **Number**, **Boolean**, or **Null** for typed values, and **Object** or **Array** for structured JSON. Switching scopes retains draft edits.
4. Choose **Save client** to persist the mappings. Inline messages explain invalid values, reserved claims, and scopes that cannot currently be requested.

The editor stores the same scope-keyed JSON structure as before, for example:

```json
{
  "api.read": { "role": "service", "tenant": "sandbox" },
  "api.write": { "write_permission": true }
}
```

Only claims for granted scopes are emitted. Reserved token fields and standard user-profile fields cannot be overridden. Application claims are separate from configured-user claims and persist in each client's `claimsByScope` object. Existing settings without this field load with an empty object.

Tokens use RS256 with a persisted RSA key. Codes default to 5 minutes, access/ID tokens to 1 hour, and refresh tokens to 30 days. `openid` requests receive ID tokens; `offline_access` grants receive refresh tokens. Refresh rotates tokens; reuse invalidates the family. Codes and refresh tokens are in memory and invalid after restart. Signed access/ID tokens remain cryptographically valid against the current key until expiry or admin key rotation; local userinfo additionally checks the issuing client's effective issuer/audience and enabled status. Changing the listening port changes the default issuer; configured client issuer overrides remain unchanged.

### Token introspection

OAuthSim access tokens are signed RS256 JWTs, not encrypted tokens. APIs can validate them locally using discovery/JWKS, checking the signature, expected issuer and audience, expiry, and allowed algorithm. For a server-side validity check, use [RFC 7662 token introspection](https://www.rfc-editor.org/rfc/rfc7662):

```sh
curl -u my-client:my-secret http://localhost:42069/oauth/v2/introspect \
  --data-urlencode "token=<access-token>" \
  -d token_type_hint=access_token
```

The request must use `application/x-www-form-urlencoded`. Each issuing client's admin Settings tab has a **Require Basic authentication for introspection** switch, ON by default (including existing settings). When ON, authenticate an enabled confidential client using `Authorization: Basic <base64(ClientId:ClientSecret)>`, as generated by `curl -u`. OAuth Basic credentials with reserved characters should be form-URL-encoded before joining with `:` and Base64 encoding. Form fields `client_id` and `client_secret` cannot authenticate introspection; `client_secret` form fields are rejected. Basic-authenticated callers can inspect an access token only if its `aud` contains their Client ID, using exact, case-sensitive membership in a string or string array. This applies even when the caller acquired the token itself, or the issuing client's switch is OFF.

For example, register a public `my-spa` client and a confidential `my-server` client. Set the SPA's **Access-token audiences** to `my-server`. After the SPA obtains a token using S256 PKCE and sends it to the server, the server calls:

```sh
curl -u my-server:server-secret http://localhost:42069/introspect \
  --data-urlencode "token=<spa-access-token>"
```

The active response retains `client_id: "my-spa"` and `aud: "my-server"`; the SPA's ID-token audience remains `my-spa`. The SPA does not need the server's secret. Servers must also enforce required scopes/permissions for their endpoints. With multiple configured API audiences, each listed confidential server can introspect using its own credentials.

When the switch is OFF, send only the token, without credentials:

```sh
curl http://localhost:42069/oauth/v2/introspect \
  --data-urlencode "token=<access-token>"
```

OAuthSim infers the issuing client only after validating the access token, then checks that client's current switch. A supplied `client_id` cannot select an anonymous client's policy. Public clients can use this anonymous mode, but cannot authenticate with Basic. When their switch is ON, an audience-matched confidential server can still introspect their tokens. Invalid supplied Basic credentials always fail; they do not fall back to anonymous inspection. Switch and credential edits take effect without restart and persist. The admin Integration tab reflects the selected mode.

An active response includes `active: true`, `token_type: "Bearer"`, and the validated JWT claims, including `client_id`, `sub`, `scope`, `iss`, `aud`, `iat`, `exp`, and any granted profile/custom claims with their original JSON types. Both user and application access tokens are supported. Introspection metadata cannot be overridden by custom claims.

Invalid, expired, tampered, reset-invalidated, or audience-unauthorized tokens return HTTP 200 with only `{"active":false}`. Malformed token audiences (empty arrays, non-string entries, or blank identifiers) are inactive. Anonymous invalid tokens also return inactive because no trusted client can be inferred, even when all clients require Basic. ID tokens and refresh tokens also return inactive; introspection currently supports access tokens only. `token_type_hint` is optional and advisory, including unfamiliar hints. Invalid credentials (including disabled/public clients), or anonymous inspection of a valid token whose client requires Basic, return HTTP 401 `invalid_client` with a Basic challenge. Missing/blank tokens, duplicate form parameters, incorrect content types, or `client_secret` form fields return HTTP 400 `invalid_request`. Responses are not cacheable (`Cache-Control: no-store`, `Pragma: no-cache`). Global token invalidation makes old tokens inactive immediately; a same-issuer restart preserves access-token validity while the signing key remains unchanged.

## Identity and claims

Clients without users accept an email. Configured clients show enabled users in a passwordless picker. Country defaults to Philippines. Browser language is matched to the selected country's supported languages, otherwise `en`. Successful selections are remembered per client; changing configured users loads their profile defaults.

`email` grants emit email; `profile` grants emit name, ISO country, language, and locale. All identities have a stable `sub`. Ad-hoc email identities are client-scoped and are not automatically added to the user list. Custom claims use scope-keyed JSON, for example `{"roles":{"role":"tester"}}`; token and standard identity fields cannot be overridden.

The embedded country/language catalog is a curated ISO-country list informed by [Unicode CLDR territory-language information](https://unicode.org/cldr/charts/latest/supplemental/territory_language_information.html), not an exhaustive population-language dataset. English is an explicit simulator fallback for every country. Country/language names come from .NET/ICU and browser Intl; the UI stays in English.

Browser token/userinfo requests allow CORS from configured redirect origins, and loopback origins when redirects are unconfigured or relaxed. Admin is available on the configured public URL and local backend, with antiforgery-protected mutation forms. Stored mock secrets and the private signing key are readable by the current user; use development credentials.

## Development checks

```sh
dotnet build OAuthSim.slnx -c Release
dotnet run --project tests/OAuthSim.Tests -c Release
```

The integration runner exercises real HTTP endpoints, admin forms, persistence, code expiry/replay, PKCE, JWT signatures, refresh rotation/reuse, client-credentials authentication/scopes/application claims, per-client issuer/audience overrides, client-specific discovery, and a standard ASP.NET Core OIDC client's sign-in callback with default and custom issuers. It also checks forwarded HTTPS, trusted proxy networks, public hostname/path discovery and token identity, prefixed admin/login flows, secure cookies, and native HTTPS with multiple listeners. Pass an installed tool executable as its argument to run the same suite against the package.

Application-claims editor logic can also be checked with Node.js, without installing frontend dependencies:

```sh
node --test tests/OAuthSim.Tests/ApplicationClaimsEditor.test.cjs
```

For real-browser editor checks, use Playwright with Chromium installed:

```sh
node tests/browser-application-claims.cjs <path-to-playwright-module>
```

This checks typed values, lossless large numbers, scoped token emission, validation before HTMX submission, save/reload behavior, live scope-policy guidance, client isolation, issuer/audience controls and discovery, and responsive light/dark styling. It also accepts an installed tool executable as a second argument and `OAUTHSIM_SHOTS=<directory>` for screenshots.

The real-browser email-login regression check requires Playwright with Chromium installed:

```sh
node tests/browser-login.cjs <path-to-playwright-module>
```

It verifies email/English submission, welcome-back countdown, destination completion, logout cancellation, prompt/max_age handling, form_post session reuse, the HTMX global reset, admin tab persistence across HTMX swaps, nested user forms, clipboard copy, dark-scheme rendering and reduced-motion behavior, and fails on any browser page error. Set `OAUTHSIM_TEST_PROXY=1` to run the same suite through a prefix-stripping reverse proxy at `/oauthsim`. Optionally pass an installed tool executable as the second argument to test the package. Set `OAUTHSIM_SHOTS=<directory>` to also save light/dark desktop and mobile screenshots.
