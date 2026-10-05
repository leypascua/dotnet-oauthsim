# OAuthSim

A .NET 10 CLI tool hosting a local OAuth 2.0 / OpenID Connect server with a responsive browser-based admin page.

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

## Configuration

Settings live in `~/.oauth-sim/settings.json` (`%USERPROFILE%\.oauth-sim\settings.json` on Windows). Clients, users, signing keys, token lifetimes, and per-client last successful login selections survive restarts. Writes are atomic with a `settings.json.bak` backup. A lock prevents simultaneous writers; use separate settings directories to run multiple servers. A malformed document is preserved and startup fails with recovery instructions.

The admin page shows the server endpoints, token lifetimes and the global reset, then one card per client with Settings, Users and Integration tabs (the active tab is remembered per client for the browser session). It supports public/confidential authentication, redirect URIs, allowed scopes, users, scoped custom JSON claims, copyable client IDs/secrets, and ready-to-use authorization URL and curl examples. Empty redirect/scope lists accept values from the request; configured lists validate exact redirect URIs and allowed scopes unless their relaxed switch is enabled. Unknown/disabled clients are rejected. Startup prints credentials only when one client exists. Explicit busy ports fail; saved/default busy ports fall back to an available port.

## Endpoints

| Endpoint | Behavior |
|---|---|
| `/oauth/v2/authorize` | Authorization code login, query or `form_post` response |
| `/oauth/v2/token` | Code exchange, client credentials, and rotating refresh tokens |
| `/oauth/v2/userinfo` | GET/POST with bearer access token |
| `/oauth/v2/introspect` | POST to validate and inspect same-client access tokens (RFC 7662) |
| `/.well-known/openid-configuration` | OIDC discovery |
| `/oauth/v2/jwks` | Public RS256 keys |

`/authorize`, `/token`, `/userinfo`, and `/introspect` are aliases. Issuer is the printed `http://localhost:<port>` origin. Configure OIDC clients to allow HTTP metadata during local development (ASP.NET Core: `RequireHttpsMetadata = false`).

Confidential clients support `client_secret_basic` and `client_secret_post`. Public clients require S256 PKCE and no secret. Supported grants are `authorization_code`, `refresh_token`, and `client_credentials` (confidential clients only). Request objects and implicit/hybrid flows are not implemented.

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

The response contains `access_token`, `token_type: "Bearer"`, `expires_in`, and the granted `scope`. It never contains an ID token or refresh token. The JWT uses the same persisted RS256 key and configured access-token lifetime as user tokens, with the client ID as `sub` and `aud`, plus `client_id` and `grant_type: "client_credentials"`.

An omitted or empty scope grants no scopes. A configured allowed-scope list is enforced unless relaxed; an empty list accepts requested API scopes. `openid`, `profile`, `email`, and `offline_access` are always rejected with `invalid_scope` for this grant. Application tokens cannot call `/userinfo`, which returns HTTP 403 `insufficient_scope`; use these tokens with your application APIs instead.

In the admin client's **Application claims by scope** field, configure machine claims such as:

```json
{
  "api.read": { "role": "service", "tenant": "sandbox" },
  "api.write": { "write_permission": true }
}
```

Only claims for granted scopes are emitted. Reserved token fields and standard user-profile fields cannot be overridden. Application claims are separate from configured-user claims and persist in each client's `claimsByScope` object. Existing settings without this field load with an empty object.

Tokens use RS256 with a persisted RSA key. Codes default to 5 minutes, access/ID tokens to 1 hour, and refresh tokens to 30 days. `openid` requests receive ID tokens; `offline_access` grants receive refresh tokens. Refresh rotates tokens; reuse invalidates the family. Codes and refresh tokens are in memory and invalid after restart. Signed access/ID tokens remain cryptographically valid against the current key until expiry or admin key rotation; local userinfo additionally checks issuer and enabled client. Changing the listening port changes the issuer.

### Token introspection

OAuthSim access tokens are signed RS256 JWTs, not encrypted tokens. APIs can validate them locally using discovery/JWKS, checking the signature, expected issuer and audience, expiry, and allowed algorithm. For a server-side validity check, use [RFC 7662 token introspection](https://www.rfc-editor.org/rfc/rfc7662):

```sh
curl -u my-client:my-secret http://localhost:42069/oauth/v2/introspect \
  --data-urlencode "token=<access-token>" \
  -d token_type_hint=access_token
```

The request must use `application/x-www-form-urlencoded`. Authenticate an enabled confidential client with HTTP Basic or form fields `client_id` and `client_secret`, using only one method. Public clients cannot authenticate to introspection. OAuthSim's initial policy permits inspecting only access tokens issued to the calling client; this ownership restriction is a simulator policy, not an RFC requirement. The admin Integration tab includes an example and guidance for public clients.

An active response includes `active: true`, `token_type: "Bearer"`, and the validated JWT claims, including `client_id`, `sub`, `scope`, `iss`, `aud`, `iat`, `exp`, and any granted profile/custom claims with their original JSON types. Both user and application access tokens are supported. Introspection metadata cannot be overridden by custom claims.

Invalid, expired, tampered, reset-invalidated, or other-client tokens return HTTP 200 with only `{"active":false}`. ID tokens and refresh tokens also return inactive; introspection currently supports access tokens only. `token_type_hint` is optional and advisory, including unfamiliar hints. Invalid credentials (including disabled/public clients) return HTTP 401 `invalid_client` with a Basic challenge. Missing/blank tokens, duplicate form parameters, incorrect content types, or combined authentication methods return HTTP 400 `invalid_request`. Responses are not cacheable (`Cache-Control: no-store`, `Pragma: no-cache`). Global token invalidation makes old tokens inactive immediately; a same-issuer restart preserves access-token validity while the signing key remains unchanged.

## Identity and claims

Clients without users accept an email. Configured clients show enabled users in a passwordless picker. Country defaults to Philippines. Browser language is matched to the selected country's supported languages, otherwise `en`. Successful selections are remembered per client; changing configured users loads their profile defaults.

`email` grants emit email; `profile` grants emit name, ISO country, language, and locale. All identities have a stable `sub`. Ad-hoc email identities are client-scoped and are not automatically added to the user list. Custom claims use scope-keyed JSON, for example `{"roles":{"role":"tester"}}`; token and standard identity fields cannot be overridden.

The embedded country/language catalog is a curated ISO-country list informed by [Unicode CLDR territory-language information](https://unicode.org/cldr/charts/latest/supplemental/territory_language_information.html), not an exhaustive population-language dataset. English is an explicit simulator fallback for every country. Country/language names come from .NET/ICU and browser Intl; the UI stays in English.

Browser token/userinfo requests allow CORS from configured redirect origins, and loopback origins when redirects are unconfigured or relaxed. Admin is loopback-only with antiforgery-protected mutation forms. Stored mock secrets and the private signing key are readable by the current user; use development credentials.

## Development checks

```sh
dotnet build OAuthSim.slnx -c Release
dotnet run --project tests/OAuthSim.Tests -c Release
```

The integration runner exercises real HTTP endpoints, admin forms, persistence, code expiry/replay, PKCE, JWT signatures, refresh rotation/reuse, client-credentials authentication/scopes/application claims, and a standard ASP.NET Core OIDC client's sign-in callback. Pass an installed tool executable as its argument to run the same suite against the package.

The real-browser email-login regression check requires Playwright with Chromium installed:

```sh
node tests/browser-login.cjs <path-to-playwright-module>
```

It verifies email/English submission, welcome-back countdown, destination completion, logout cancellation, prompt/max_age handling, form_post session reuse, the HTMX global reset, admin tab persistence across HTMX swaps, nested user forms, clipboard copy, dark-scheme rendering and reduced-motion behavior, and fails on any browser page error. Optionally pass an installed tool executable as the second argument to test the package. Set `OAUTHSIM_SHOTS=<directory>` to also save light/dark desktop and mobile screenshots.
