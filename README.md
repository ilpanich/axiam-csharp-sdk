# Axiam.Sdk (C#)

[![CI](https://github.com/ilpanich/axiam-csharp-sdk/actions/workflows/sdk-ci-csharp.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-csharp-sdk/actions/workflows/sdk-ci-csharp.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-csharp-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-csharp-sdk?branch=main)
[![NuGet Axiam.Sdk](https://img.shields.io/nuget/v/Axiam.Sdk.svg?label=NuGet%3A%20Axiam.Sdk)](https://www.nuget.org/packages/Axiam.Sdk)
[![NuGet Axiam.Sdk.AspNetCore](https://img.shields.io/nuget/v/Axiam.Sdk.AspNetCore.svg?label=NuGet%3A%20Axiam.Sdk.AspNetCore)](https://www.nuget.org/packages/Axiam.Sdk.AspNetCore)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official C# client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

**Platform documentation:** <https://ilpanich.github.io/axiam/> — getting started, the authorization model, the OAuth2/OIDC surface, and the operations guides. This README covers the SDK; the site covers the server it talks to.

## Package identity

- **NuGet packages:** [`Axiam.Sdk`](https://www.nuget.org/packages/Axiam.Sdk) (core) and
  [`Axiam.Sdk.AspNetCore`](https://www.nuget.org/packages/Axiam.Sdk.AspNetCore) (ASP.NET Core middleware)
- **Source:** [github.com/ilpanich/axiam-csharp-sdk](https://github.com/ilpanich/axiam-csharp-sdk)
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1–§13 and §12.7, §14, §15, §17, §19, §20, §22, §23, §24, §25,
§26 (including §6.1 mTLS client certificates, the §1.1 gRPC-only `get_user_info` operation, contract
1.3, the §12 OIDC/SSO relying-party helpers, contract 1.4, the §13 webhook signature verifier, T-145,
the §20 UMA 2.0 Protection API and ticket grant, contract 1.10, the §22 reactor runtime, contract
1.19, the §23 OPAQUE (RFC 9807) login path, contract 1.26, the §24 WebAuthn relying-party layer,
the §25 account-lifecycle operations and §26 Pushed Authorization Requests, contract 1.28, and
§23.4 rule 7's `mode`-driven password-login fallback, contract 1.29).

§12.7, §14, §15, §20, §22, §23, §24, §25 and §26 are named rather than folded into the range because
they landed after this SDK already claimed §1–§13: widening the range silently would turn a
statement that was true when written into a different claim without anyone editing it.

§24.6b — the linked-API ceremony helper — is **deliberately absent**. A server or CLI runtime has no
authenticator, and §24.6b rule 2 forbids emulating one in software: a "credential" held in process
memory is not a second factor. §24.6a's JSON bridge is what a Blazor, MAUI or Uno front end uses
instead — see [WebAuthn / passkeys](#webauthn--passkeys-axiamsdkwebauthn-contractmd-24).

See [`CONTRACT.md`](CONTRACT.md) for the full cross-language behavioral contract.

### §1–§13 conformance checklist

| § | Requirement | Where implemented |
|---|---|---|
| §1 | PascalCase method map (`Login`/`VerifyMfa`/`Refresh`/`Logout`/`CheckAccess`/`Can`/`BatchCheck`) | `AxiamClient.LoginAsync`/`VerifyMfaAsync`/`RefreshAsync`/`LogoutAsync`; `AuthzRestClient.CheckAccessAsync`/`CanAsync`/`BatchCheckAsync`; `Grpc/AxiamGrpcAuthzClient.CheckAccessAsync`/`BatchCheckAsync` |
| §1.1 | gRPC-only `GetUserInfoAsync` (`axiam.v1.UserInfoService/GetUserInfo`) — empty request, identity from the bearer token; returns typed `UserInfo { Sub, TenantId, OrgId, Email?, PreferredUsername? }` (scope-gated optionals); reuses the same channel/interceptor/refresh machinery as `CheckAccess`; no REST substitution | `Grpc/AxiamGrpcAuthzClient.GetUserInfoAsync`, `Grpc/UserInfo.cs` |
| §2 | `AuthError`/`AuthzError`/`NetworkError` taxonomy + HTTP/gRPC status mapping | `Core/ErrorMapper.cs`, `Core/AuthError.cs`, `Core/AuthzError.cs`, `Core/NetworkError.cs` |
| §3 | Non-browser CSRF: capture `X-CSRF-Token` response header, echo on state-changing requests | `Rest/AxiamHttpMessageHandler.cs` |
| §4 | Persistent cookie jar (`HttpClientHandler { UseCookies = true, CookieContainer = new() }`) | `Rest/AxiamHttpClientFactory.cs` |
| §5 | Tenant is a required, non-optional constructor parameter | `AxiamClient`'s single public constructor (SC#1) |
| §6 | Strict TLS always on; only escape hatch is a `customCa` chain-trust callback — no bypass surface | `Rest/AxiamHttpClientFactory.CreatePrimaryHandler` (verified by the `TlsBypassGrepGateTests` xUnit test + a CI grep gate, SC#4) |
| §6.1 | Optional client-certificate / mutual-TLS (mTLS) identity (`ClientCertificatePem` + `ClientKeyPem`), applied to **both** REST and gRPC transports; strict server verification stays on (separate code path from §6) | `Options/AxiamClientOptions.ClientCertificatePem`/`ClientKeyPem` → `Rest/AxiamHttpClientFactory.CreatePrimaryHandler`/`ConfigureFactoryHandler` + `Grpc/AxiamGrpcChannel.Create` |
| §7 | `Sensitive<T>` struct redacting `ToString()`/JSON to `"[SENSITIVE]"` | `Core/Sensitive.cs` |
| §8 | AMQP HMAC-SHA256 verify-before-handler, constant-time compare, NEW-4 replay protection (`key_version`/`nonce`/`issued_at`) | `Amqp/Hmac.cs`, `Amqp/AxiamAmqpConsumer.cs`, `Amqp/ReplayGuard.cs` |
| §9 | `SemaphoreSlim(1,1)` single-flight refresh, one guard across REST + gRPC | `Auth/RefreshGuard.cs` (shared by `AxiamClient` and `Grpc/AuthInterceptor.cs`) |
| §10 | `app.UseMiddleware<AxiamAuthMiddleware>()` + `ClaimsPrincipal` injection + policy-based `[Authorize]` | `Axiam.Sdk.AspNetCore/AxiamAuthMiddleware.cs`, `AxiamPolicyHandler.cs`/`AxiamPolicyProvider.cs` |
| §10.1 | Complete minimum local-verification set: EdDSA-pinned signature (before key lookup), **required** `exp`, honoured `nbf`, asserted `tenant_id`, conditional `iss`/`aud`, named 60s clock skew — all fail-closed | `Auth/JwksVerifier.VerifyAsync`/`ApplyClaimPolicy`, exercised by `tests/Axiam.Sdk.Tests/Contract101LocalVerificationTests.cs` |
| §11 | Declarative `[AxiamAccess(action, resource)]` authorization attribute with scope + route-param resolution; `require_auth`/`require_role` as framework-native `[Authorize]`/`[Authorize(Roles = ...)]` | `Axiam.Sdk.AspNetCore/AxiamAccessAttribute.cs`, `AxiamRequirement.cs`, `AxiamPolicyHandler.cs`/`AxiamPolicyProvider.cs` |
| §12 | OIDC/SSO relying-party helpers: `OidcDiscoverAsync`/`OidcBegin`/`OidcExchangeAsync`/`OidcRefreshAsync`/`LoginClientCredentialsAsync`/`IntrospectAsync`/`RevokeAsync`/`SsoStartAsync`/`SsoCompleteAsync`; `MapAxiamOidcLogin` ASP.NET Core glue | `AxiamClient.Oidc.cs`, `Auth/Oidc/*.cs`, `Axiam.Sdk.AspNetCore/OidcLoginEndpoints.cs` |
| §13 | Webhook signature verifier: HMAC-SHA256 over `<t>.<raw_body>`, `CryptographicOperations.FixedTimeEquals` constant-time compare on decoded bytes, two-sided 300s default freshness tolerance, `TimeProvider` injection seam, fail-closed on malformed/tampered input | `Webhooks/AxiamWebhooks.cs`, `Webhooks/WebhookEvent.cs`, `Webhooks/WebhookVerificationException.cs` |
| §22 | Reactor runtime — AMQP extension actors: `ReactorServeAsync` consumes the **server-declared** queue, verifies each event under §8 v2 before the handler sees it, and signs the reply with the same tenant subkey. The reactor canonicalization differs from §8's in exactly one place (`hmac_signature` serialized as **`null`**, not omitted), proven byte-for-byte against the server-generated §22.13 vectors. §22.7's hot-path exclusion is asserted against the constant list. | `Reactor/ReactorProtocol.cs`, `Reactor/ReactorServer.cs`, `Reactor/ReactorEvents.cs`, `Reactor/ReactorDecision.cs`, `Reactor/ReactorEvent.cs`, `Reactor/ReactorServeOptions.cs` |

## Local token verification (CONTRACT.md §10.1)

`AxiamAuthMiddleware` verifies access tokens locally through one implementation,
`JwksVerifier.VerifyAsync`, which applies the **complete** §10.1 minimum
local-verification set. Every rule fails closed — a required claim that is absent,
unparseable, or of the wrong JSON type is a rejection, never a skipped check.

| # | Claim | What the verifier does |
|---|---|---|
| 1 | signature | Verified against the org-wide JWKS with `alg` pinned to `EdDSA` **before** any `kid` lookup, so `alg: none` and HS-family confusion are rejected without ever consulting a key. |
| 2 | `exp` | **Required.** No `exp`, or an `exp` that is not a JSON number, is rejected. An absent `exp` is a permanent credential, not an absent constraint. |
| 3 | `nbf` | Honoured when present; an `nbf` in the future is rejected. An absent `nbf` is valid. |
| 4 | `tenant_id` | **Required and asserted** against the configured tenant. An absent claim — or an empty configured tenant — is rejected. The JWKS is organization-wide, so a valid signature alone never bounds a token to a tenant. |
| 5 | `iss` | Checked **only** when `ExpectedIssuer` is configured. Unset by default. |
| 6 | `aud` | Checked **only** when `ExpectedAudience` is configured. Unset by default; accepts both the single-string and array forms. |
| 7 | clock skew | `JwksVerifier.ClockSkewLeeway` — a named 60-second constant applied to rules 2 and 3. Deliberately **not** operator-configurable. |

This SDK uses **no JWT library**: there is no `System.IdentityModel.Tokens.Jwt`,
`JwtSecurityTokenHandler`, or `TokenValidationParameters` anywhere in the dependency
graph (.NET ships no Ed25519 primitive, so JOSE processing is hand-rolled over
BouncyCastle). Every rule above is enforced explicitly rather than inherited from a
library default.

`iss` and `aud` are conditional and default to unset; no issuer or audience is hardcoded
anywhere. Configure them when your deployment has an expectation to assert — an app
guarding a user-facing resource server should generally expect `axiam:user`:

```csharp
services.AddAxiamAspNetCore(options =>
{
    options.BaseUrl = new Uri("https://axiam.example.com");
    options.DefaultTenantId = "acme";

    // CONDITIONAL (§10.1 rules 5 and 6). Omit either one to skip that check entirely.
    options.ExpectedIssuer = "https://axiam.example.com";
    options.ExpectedAudience = "axiam:user";
});
```

## Declarative authorization helpers (CONTRACT.md §11)

`Axiam.Sdk.AspNetCore` ships a declarative, per-endpoint authorization attribute built
strictly on top of the §10 middleware — it never re-implements or bypasses JWKS
verification, the tenant check, or §3a CSRF; it only consumes the identity
`AxiamAuthMiddleware` already injected into `HttpContext.User`.

```csharp
using Axiam.Sdk.AspNetCore;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api")]
public sealed class DocumentsController : ControllerBase
{
    // action = "read", resource type = "documents" (sent to CheckAccessAsync as
    // "documents:read", the server's own "resource:verb" convention). The resource
    // UUID is resolved from the "id" route value by default.
    [HttpGet("documents/{id:guid}")]
    [AxiamAccess("read", "documents")]
    public IActionResult GetDocument(Guid id) => Ok(new { id });

    // Scope + a non-default route parameter name.
    [HttpGet("teams/{teamId:guid}/documents")]
    [AxiamAccess("list", "documents", Scope = "team", ResourceRouteParam = "teamId")]
    public IActionResult ListTeamDocuments(Guid teamId) => Ok(new { teamId });
}
```

`[AxiamAccess(action, resource)]` is sugar over the existing
`[Authorize(Policy = "resource:action")]` mechanism (`AxiamPolicyProvider`/
`AxiamPolicyHandler`) — the legacy `"resource:action"` policy-string form remains
fully supported side by side with the new attribute.

Semantics (CONTRACT.md §11.2, identical to every other AXIAM SDK):

- **Runs strictly after authentication.** No verified identity in `HttpContext.User` →
  `401 authentication_failed`. The attribute never performs its own token extraction.
- **Subject propagation.** The check is made for the *request's* authenticated user
  (`subjectId` = the `user_id` claim `AxiamAuthMiddleware` injected), never for the
  shared `AxiamClient`'s own session.
- **Resource resolution.** The resource UUID is resolved from the route value named by
  `ResourceRouteParam` (default `"id"`). A missing or non-UUID route value is a
  **programming error** → `400 invalid_request` — never a silent allow, never a
  `Guid.Empty`/nil-UUID fallback.
- **Scope.** The optional `Scope` property is passed through to `CheckAccessAsync`
  verbatim.
- **Fail-closed on transport failure.** A `NetworkError` while calling the authz
  endpoint → `503 authz_unavailable` — deny, never allow, on a transport failure.
- **No decision caching.** Every check is a fresh `CheckAccessAsync` call, exactly like
  the legacy policy-string form.
- **Deny outcome.** `403 authorization_denied`.

`require_auth` and `require_role` are not new types in this SDK — they map directly
onto ASP.NET Core's own `[Authorize]` and `[Authorize(Roles = "admin,editor")]`
(`AxiamAuthMiddleware` already emits a `ClaimTypes.Role` claim per role, so
role-based `[Authorize]` works out of the box). `require_role` is a **local** check
against the verified token's claims — it never calls the AXIAM server, and it is
documented here (as in every AXIAM SDK) as NOT a substitute for the resource-level
`[AxiamAccess(...)]` check above.

## OIDC / SSO relying-party helpers (CONTRACT.md §12)

`Axiam.Sdk` ships the nine canonical §12 operations directly on the existing
`AxiamClient` (no separate client type) — "Login with AXIAM" via authorization-code +
PKCE, service-account login via `client_credentials`, token introspection/revocation, and
the upstream-IdP federation pair:

| Canonical operation | C# method |
|---|---|
| `oidc_discover` | `OidcDiscoverAsync` |
| `oidc_begin` | `OidcBegin` — **no `Async` suffix**: pure local computation, no network I/O (the one deliberate exception to the SDK's `*Async` naming rule) |
| `oidc_exchange` | `OidcExchangeAsync` |
| `oidc_refresh` | `OidcRefreshAsync` |
| `login_client_credentials` | `LoginClientCredentialsAsync` |
| `introspect` | `IntrospectAsync` |
| `revoke` | `RevokeAsync` |
| `sso_start` | `SsoStartAsync` |
| `sso_complete` | `SsoCompleteAsync` |

```csharp
using Axiam.Sdk;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Options;

var baseUrl = new Uri("https://your-axiam-instance");
using var client = new AxiamClient(baseUrl, "your-tenant-slug", new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = "your-tenant-slug",
    // client_id/client_secret are CLIENT CONFIGURATION (CONTRACT.md §12.1) — never a
    // per-call argument. Omit OidcClientSecret for a public client.
    OidcClientId = "your-relying-party-client-id",
});

// 1. Fetch (and cache — §12.3 rule 6) the discovery document.
OidcConfiguration configuration = await client.OidcDiscoverAsync();

// 2. Build the authorization request — PURE LOCAL COMPUTATION, no network I/O.
//    The SDK stores NOTHING: persist State/Nonce/CodeVerifier yourself (your own
//    HTTP session, or the optional IOidcStateStore) and redirect the browser to Url.
AuthorizationRequest request = client.OidcBegin(configuration, new OidcBeginParams
{
    RedirectUri = "https://your-app/callback",
});
// redirect the browser to request.Url; stash request.State/Nonce/CodeVerifier

// 3. On the callback, exchange the code — validates the id_token in FULL (§12.4)
//    before returning; on any failure the whole token set is discarded (§12.4 rule 7).
OidcTokenSet tokens = await client.OidcExchangeAsync(new OidcExchangeParams
{
    Code = "<code from the callback query string>",
    CodeVerifier = request.CodeVerifier,   // the SAME Sensitive<string> from step 2
    RedirectUri = "https://your-app/callback",
    Nonce = request.Nonce,
});

// AccessToken/RefreshToken/IdToken are Sensitive<string> (§12.5) — Expose() is the
// documented §7-vs-§12 accessor: unlike the §1–§11 cookie-session surface, §12
// delivers tokens directly in the response body, so the caller must be able to read
// them back out to persist/forward/revoke them. ToString()/JSON serialization still
// always redact regardless.
string accessToken = tokens.AccessToken.Expose();
string? subject = tokens.IdClaims?.Sub;
```

**ASP.NET Core "Login with AXIAM" glue** — `Axiam.Sdk.AspNetCore` provides
`MapAxiamOidcLogin`, wiring the login-redirect and callback endpoints into the existing
minimal-API pipeline, backed by an `IOidcStateStore` (`MemoryOidcStateStore` by default,
registered by `AddAxiam`/`AddAxiamAspNetCore`) that links the two requests of the flow:

```csharp
using Axiam.Sdk.AspNetCore;

builder.Services.AddAxiamAspNetCore(options =>
{
    options.BaseUrl = new Uri("https://your-axiam-instance");
    options.DefaultTenantId = "your-tenant-slug";
    options.OidcClientId = "your-relying-party-client-id";
});

var app = builder.Build();
// ...
app.MapAxiamOidcLogin("/login/axiam", "/login/axiam/callback", options =>
{
    options.RedirectUri = "https://your-app/login/axiam/callback";
    options.SuccessRedirect = "/dashboard";
    // The caller owns what a session means (§12 leaves this to the application) —
    // this is where you sign your OWN cookie / write your OWN session row.
    options.OnSuccessAsync = (context, tokens, entry, cancellationToken) =>
    {
        // e.g. context.Response.Cookies.Append("your_app_session", ...);
        return Task.CompletedTask;
    };
});
```

Notes:

- **Caller owns all state (§12.3 rule 1).** `OidcBegin`/`OidcExchangeAsync` never store
  `state`/`nonce`/`code_verifier` anywhere — your own HTTP session (or `IOidcStateStore`
  for the ASP.NET Core glue) is the only place they live between the redirect and the
  callback. `MemoryOidcStateStore` is a single-process, 10-minute-TTL, single-use
  reference implementation — a multi-instance deployment needs a shared store (Redis, a
  database): implement `IOidcStateStore` directly.
- **S256-only PKCE.** `"plain"` is never emitted, never accepted, and not configurable.
- **`client_id` is client configuration** (`AxiamClientOptions.OidcClientId`), never a
  per-call argument — required before any §12 operation other than `OidcDiscoverAsync`.
- **`oidc_refresh` is distinct from `RefreshAsync`.** The §1 cookie/opaque-token session
  refresh and the §12 OAuth2 `refresh_token` grant are never merged, aliased, or made to
  fall back to one another.
- **`IntrospectAsync`/`RevokeAsync`/`LoginClientCredentialsAsync` require a confidential
  client** (`OidcClientSecret` configured) — a public client gets `AuthError`, client-side,
  with no wire call.
- **`RevokeAsync` is idempotent** (RFC 7009): any `2xx`, including for a token the server
  has never seen, is success.
- **A `401` from `/oauth2/introspect`/`/oauth2/revoke` never triggers the §9 refresh
  guard** — a bad `client_secret` is not a session expiry.
- **`OAuthProtocolError`** (an RFC 6749 `OAuth2ErrorResponse` body) is a sub-type of
  `AuthError` — existing `catch (AuthError ex)` blocks keep working unchanged; it
  additionally exposes `Error`/`ErrorDescription`.
- **ID-token validation (§12.4)** checks `alg` (EdDSA only), signature (via the same
  JWKS verifier the §10 middleware uses), `iss`, `aud`/`azp`, `exp`/`iat`/`nbf` (±60s
  skew), and `nonce`. Any failure raises `AuthError` with a stable `Reason` — one of
  `invalid_alg`, `unknown_kid`, `invalid_signature`, `invalid_issuer`,
  `invalid_audience`, `token_expired`, `nonce_mismatch` — and discards the entire token
  set (no partial success).

See [`examples/AspNetCoreSample`](examples/AspNetCoreSample) for a runnable
`MapAxiamOidcLogin` wiring and [`examples/Quickstart`](examples/Quickstart) for the
`LoginClientCredentialsAsync`/`IntrospectAsync`/`RevokeAsync` machine-to-machine flow.

## Quickstart

```bash
dotnet add package Axiam.Sdk
dotnet add package Axiam.Sdk.AspNetCore   # optional — ASP.NET Core middleware + DI
```

```csharp
using Axiam.Sdk;
using Axiam.Sdk.Options;

// tenantId is a required, positional constructor argument (SC#1) — there is no
// overload or default that omits it (CONTRACT.md §5). login/refresh additionally
// require organization context — a tenant slug is only unique within an
// organization — so supply OrgSlug (or OrgId) via AxiamClientOptions; a login
// body without it is rejected with 400 "must provide org_id or org_slug"
// (CONTRACT.md §5.1).
var baseUrl = new Uri("https://your-axiam-instance");
using var client = new AxiamClient(baseUrl, "your-tenant-slug", new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = "your-tenant-slug",
    OrgSlug = "your-org-slug",
});

var login = await client.LoginAsync("alice@example.com", "correct horse battery staple");
if (login.MfaRequired)
{
    login = await client.VerifyMfaAsync(login.ChallengeToken!.Value, totpCode: "123456");
}

bool canRead = await client.Authz.CanAsync("documents:read", documentId);
```

See [`examples/`](examples/) for a full runnable ASP.NET Core sample (middleware +
policy authorization, SC#3) and a console quickstart covering REST, gRPC, and
AMQP.

## mTLS / client certificates (CONTRACT.md §6.1)

AXIAM authenticates IoT devices and service accounts by **mutual TLS**: the client
presents an X.509 identity certificate (signed by the tenant's organization CA) that the
server binds to a service account. Configure the client identity with a PEM certificate
chain plus a PEM private key (PKCS#8 or PKCS#1) via `AxiamClientOptions` — it is applied
to **both** the REST and gRPC transports of that same client instance:

```csharp
using Axiam.Sdk;
using Axiam.Sdk.Options;

var options = new AxiamClientOptions
{
    BaseUrl = new Uri("https://your-axiam-instance"),
    TenantId = "your-tenant-slug",
    OrgSlug = "your-org-slug",                                   // org context for login/refresh (§5.1)
    ClientCertificatePem = File.ReadAllBytes("device-cert.pem"), // PEM cert chain
    ClientKeyPem = File.ReadAllBytes("device-key.pem"),          // PEM private key (secret)
};

using var client = new AxiamClient(new Uri("https://your-axiam-instance"), "your-tenant-slug", options);
```

Notes:

- **Opt-in.** Omitting the certificate leaves the SDK's default bearer-cookie behavior
  unchanged. `ClientCertificatePem` and `ClientKeyPem` must be supplied **together** —
  providing exactly one throws `ArgumentException` at client construction.
- **Strict TLS preserved.** Presenting a client certificate never relaxes server
  verification; the client-cert code path is entirely separate from §6's server-trust
  handling and installs no permissive server-validation delegate.
- **Key secrecy (§7).** The private key is secret material — it is never logged,
  serialized, or exposed via a public getter beyond the options object it is set on.
- On `Axiam.Sdk.AspNetCore`, the same two properties exist on `AxiamOptions` and flow
  through to the shared `AxiamClient`.

## UMA 2.0 — protecting resources whose owner isn't the caller (CONTRACT.md §20)

For a resource server holding data that belongs to *users*: instead of answering an
unauthorized request with a bare 403, tell the caller where to go and get authority.

Registration and the ticket grant live on `AxiamClient` (`UmaRegisterResourceAsync` /
`UmaReadResourceAsync` / `UmaUpdateResourceAsync` / `UmaDeleteResourceAsync` /
`UmaListResourcesAsync`, `UmaRequestTicketAsync`, `UmaExchangeTicketAsync`). Every
Protection API call takes the **PAT** as an explicit first argument — a client-credentials
token carrying `uma_protection` (§20.2 rule 1) rather than the client's ambient session,
because that session is usually a *user* session and a minted ticket binds to a `client_id`.

The registered id **is** the AXIAM resource id, so UMA scopes are AXIAM actions: the same
grants — deny rules included — govern an RPT-carrying request and an ordinary one.

### Emitting the challenge from the §11 policy handler

```csharp
builder.Services.AddAxiamAspNetCore(options => { /* … */ });
builder.Services.AddAxiamUmaChallenge(
    new UmaChallenger("invoices", configuration.Issuer, pat));

// A denied [Authorize(Policy="invoices:read")] now answers 403 with
//   WWW-Authenticate: UMA realm="invoices", as_uri="…", ticket="…"
```

Opt-in, deliberately: minting on every denial by default would put a Protection API call —
and a live credential — behind every unauthorized request, which is a denial-of-service
amplifier pointed at your own authorization server. And a minting failure still denies
plainly, never a 503 and never an allow. The requested scope is the AXIAM **action**, so
the ticket asks for exactly the authority just refused.

### Consuming it

`UmaChallenge.Parse(header)` parses and *stops there*. It does not exchange the ticket,
because the `as_uri` it names was chosen by the server that just refused you; auto-redeeming
would send the requesting party's token wherever a 403 pointed. The trust decision is the
caller's:

```csharp
UmaChallenge? challenge = UmaChallenge.Parse(header);
if (challenge?.Ticket is { } ticket && Trustworthy(challenge.AsUri))
{
    RequestingPartyToken rpt = await client.UmaExchangeTicketAsync(
        new UmaExchangeTicketParams(ticket, userToken));
}
```

`UmaExchangeTicketAsync` sends **one** request and never retries — the documented exception
to the §16 retry policy, because a ticket is consumed before the request is evaluated, so a
retry cannot succeed and under concurrency is exactly the double redemption to avoid. On
failure, obtain a *new* ticket.

Both halves run in [`examples/UmaResourceServer`](examples/UmaResourceServer) and
[`examples/UmaClient`](examples/UmaClient).

## Device authorization grant (CONTRACT.md §14)

RFC 8628 — signing in a device that cannot show a browser: a TV, a CLI, a headless
commissioning tool.

```csharp
OidcTokenSet tokens = await client.DeviceLoginAsync(new DeviceLoginParams(
    OnUserCode: authorization =>
    {
        // Called BEFORE the first poll, and awaited — a device rendering a QR code may
        // need a paint first. Display it however the device can; the SDK never prints it.
        Console.WriteLine($"visit {authorization.VerificationUri} and enter {authorization.UserCode}");
        return Task.CompletedTask;
    }));
```

`DeviceAuthorizeAsync` and `DevicePollAsync` are also public, for an application driving its
own loop. The polling rules are where implementations go wrong:

- **`slow_down` raises the interval permanently.** An SDK that backs off for one round and
  returns to the original interval will be told to slow down again, forever.
- **`access_denied` and `expired_token` stay distinct.** A human said no, versus nobody
  answered — the only information the device can act on.
- **Polling stops at `ExpiresIn`**, even if the server has not yet said `expired_token`.
- **A `5xx` mid-poll is not terminal.** A server restart must not lose a grant the user has
  already approved.

`DeviceCode` is `Sensitive<string>`; `UserCode` deliberately is not — it exists to be read
aloud, and wrapping it would defeat the one thing it is for. `DeviceAuthorizeAsync` sends no
`client_secret` and does not refuse a client built without one.

**`AdoptAsCredential` throws `NotSupportedException`**, exactly as
`LoginClientCredentialsAsync` does in this port: §14.3 rule 4 defers to the §12.1 adoption
MAY, and taking a second posture here would be the per-language improvisation the contract
exists to prevent.

## Token exchange (CONTRACT.md §15)

RFC 8693 — a service holding a user's token exchanging it for a *narrower* one before
calling the next service.

```csharp
ExchangedToken exchanged = await client.TokenExchangeAsync(new TokenExchangeParams(
    Sensitive<string>.Wrap(userToken),
    AxiamClient.AccessTokenType,        // required (§15.1), no default
    Scopes: new[] { "orders:read" },
    Audience: "orders-service"));
```

Most of what this method does is refuse to be helpful:

- **No default `ActorToken`.** Passing `null` asks for *impersonation*; the SDK will not
  quietly substitute the client's own session token and turn that into a delegation.
- **No auto-narrowing after `invalid_scope`.** The server refuses rather than silently
  narrowing precisely so the caller finds out here.
- **No refresh token, ever** — `ExchangedToken` has no such property. Re-run the exchange.
- **No adoption**, and no flag to enable it — a MUST NOT, where `LoginClientCredentialsAsync`
  adoption is a MAY.

### External-IdP subject tokens (CONTRACT.md §15.7)

The same method exchanges a token minted by a **trusted external IdP** — a partner's
Entra, Okta or Keycloak — for an AXIAM token scoped to what the resolved AXIAM user may
actually do. There is no separate operation:

```csharp
ExchangedToken exchanged = await client.TokenExchangeAsync(new TokenExchangeParams(
    Sensitive<string>.Wrap(partnerToken),
    SubjectTokenType: AxiamClient.JwtTokenType,   // required; named, never guessed
    Scopes: new[] { "read:orders" },
    Audience: "https://orders.internal"));
```

- **`SubjectTokenType` is yours to state, and is required** (§15.1). The SDK never decodes
  the subject token to pick it, and never overrides what you named. There is no default:
  omitting it does not compile, and `null`/blank is refused client-side with no wire call.
- **No actor token.** Delegation across a trust boundary is unsupported in v1; sending one
  is `invalid_request`, which the SDK will not work around by dropping it and re-sending.
- **One refusal is distinguishable.** `invalid_grant` whose `ErrorDescription` is `the
  subject token's issuer is not configured for token exchange` means *fix the AXIAM trust
  configuration*. Every other `invalid_grant` means *fix your token*, and is deliberately
  generic.
- **Forward the result as-is.** It carries an `ext_exchange` claim naming the partner
  issuer; never strip it, and never read it as an authorization input. It also cannot be
  exchanged again — exchanges do not compose.

The operator guide is `docs/api/federated-token-exchange.md`.

## Logout — RP-initiated and back-channel (CONTRACT.md §12.7)

`LogoutUrlAsync` builds the redirect; `VerifyLogoutTokenAsync` validates a token the OP
**pushed** to your back-channel endpoint.

```csharp
string url = await client.LogoutUrlAsync(new LogoutUrlParams(Sensitive<string>.Wrap(storedIdToken)));

// …and at your registered backchannel_logout_uri:
VerifiedLogoutToken verified = await client.VerifyLogoutTokenAsync(logoutToken);
if (verified.Sid is not null)
{
    EndSession(verified.Sid);   // that session ONLY
}
```

The verifier is where the security weight sits — the input arrives unsolicited and instructs
you to terminate a session. It checks the signature (same JWKS path and same EdDSA/`kid`
discipline as §12.4), `iss`, `aud`, that `events` carries the back-channel-logout key (**the
only thing separating a logout token from an ID token**), that `nonce` is *absent* (its
presence is how an ID token gets replayed as one), that something is named, and freshness.

It returns `Sid`/`Sub`/`Jti` rather than a bare `bool`: you have to know *which* session to
end. **Dedup on `Jti` yourself** — delivery is at-least-once, so a valid token legitimately
arrives twice; the SDK has no durable store and an in-memory guard would silently drop a real
second logout after a restart.

## Decision reason codes (CONTRACT.md §11 rule 9)

`AccessDecision.ReasonCode` distinguishes `no_grant` ("ask an admin for access") from
`denied_by_rule` ("an admin has already decided") — opposite instructions to the person on the
other end, which is why the contract forbids collapsing them into a bare `false`.

`CheckAccessAsync` and `BatchCheckAsync` keep returning `bool`/`IReadOnlyList<bool>`: those
signatures predate the field and cannot carry it. **`CheckAccessDecisionAsync` and
`BatchCheckDecisionsAsync`** — on both the REST and gRPC clients — return the full decision.
`AxiamReasonCode` holds the three defined values as constants rather than an enum, so an
unrecognised code is surfaced verbatim and never changes `Allowed`.

## Webhook signature verification (CONTRACT.md §13)

AXIAM signs every webhook delivery with a Stripe-style signed timestamp in the
`X-Axiam-Signature` header (`t=<unix_seconds>,v1=<hex_hmac_sha256>`). Verify it with
`Axiam.Sdk.Webhooks.AxiamWebhooks.Verify` before doing anything with the payload:

```csharp
using Axiam.Sdk.Core;
using Axiam.Sdk.Webhooks;

// ASP.NET Core minimal API receiver. EnableBuffering (or reading Request.Body directly,
// as below, before any model binder touches it) is required — the verifier needs the
// EXACT raw bytes that were received off the wire. Re-serializing a parsed JSON body
// changes key order/whitespace and breaks the signature.
app.MapPost("/webhooks/axiam", async (HttpRequest request) =>
{
    using var reader = new MemoryStream();
    await request.Body.CopyToAsync(reader);
    byte[] rawBody = reader.ToArray();

    string signatureHeader = request.Headers["X-Axiam-Signature"].ToString();
    Sensitive<string> webhookSecret = Sensitive<string>.Wrap(configuredWebhookSecret);

    WebhookEvent evt;
    try
    {
        evt = AxiamWebhooks.Verify(webhookSecret, signatureHeader, rawBody);
    }
    catch (WebhookVerificationException)
    {
        return Results.Unauthorized(); // invalid/stale/malformed signature — never inspect rawBody further
    }

    // evt.DeliveryId is the at-least-once dedup key (X-Axiam-Delivery) — keep a
    // short-lived seen-set, since a retry replays a valid signature within the
    // freshness window.
    return Results.Ok();
});
```

Notes:

- **Raw body only.** `Verify` MUST receive the exact bytes AXIAM sent — never a
  re-serialized/re-parsed JSON round-trip, which changes key order/whitespace and breaks
  the MAC. In ASP.NET Core, either call `HttpRequest.EnableBuffering()` before any
  middleware/model binder reads the body, or read `Request.Body` directly (as above)
  ahead of MVC model binding.
- **Constant-time, decoded-bytes comparison.** Uses
  `System.Security.Cryptography.HMACSHA256` plus `CryptographicOperations.FixedTimeEquals`
  over the *decoded* MAC bytes — never a hex-string `==` comparison, and a failed hex
  decode fails closed rather than throwing.
- **Two-sided freshness.** The default 300-second `tolerance` rejects a stale `t=` *and*
  a future-dated one (clock-skew abuse); pass a `TimeSpan` to override it, and a
  `TimeProvider` to make "now" deterministic in tests.
- **Fail closed and quiet.** Every failure — malformed header, no `v1`, tampered body,
  wrong secret, timestamp outside tolerance — throws the single
  `WebhookVerificationException`, whose message never contains the expected signature;
  the secret is never logged.
- **Dedup is the receiver's job.** `X-Axiam-Delivery` (surfaced as `WebhookEvent.DeliveryId`
  when present in the body) is the at-least-once dedup key — retries replay a valid
  signature inside the freshness window.

## Reactors — AMQP extension actors (CONTRACT.md §22)

A **reactor** is your process, subscribed to named hook events on the AXIAM AMQP bus, answering
allow / deny / mutate inside a timeout the server declared. It is AXIAM's answer to Zitadel Actions
and Keycloak SPIs, and the difference is the whole design: those load third-party code *into* the
authorization server, and this keeps it outside, reachable only through a signed reply schema the
server validates before it believes a word of it.

```csharp
using Axiam.Sdk.Core;
using Axiam.Sdk.Reactor;
using RabbitMQ.Client;

// §8b: build the factory through ReactorConnections and the transport rules hold by
// construction — amqps:// only, TLS on, no policy error tolerated, and no argument
// anywhere that turns any of that off. The second parameter is the broker's CA, for a
// privately issued certificate; pass null for a publicly issued one.
ConnectionFactory factory = ReactorConnections.CreateConnectionFactory(
    "amqps://broker.internal:5671",
    new X509Certificate2("/etc/axiam/broker-ca.pem"));
await using IConnection connection = await factory.CreateConnectionAsync();
await using IChannel channel = await connection.CreateChannelAsync();

await using ReactorServer server = await ReactorServer.ReactorServeAsync(new ReactorServeOptions
{
    Channel = channel,
    TenantId = tenantId,
    SigningKey = Sensitive<byte[]>.Wrap(subkey),   // §22.12 — a credential, never logged
    ReactorId = reactorId,                          // the queue is the server's; we only consume it
    Handler = (e, ct) => Task.FromResult(e.Event switch
    {
        ReactorEvents.TokenPreIssue =>
            ReactorDecision.Mutated(new Dictionary<string, string> { ["ext.department"] = "engineering" }),
        ReactorEvents.LoginPostAuth =>
            Embargoed(e) ? ReactorDecision.Denied("embargoed region") : ReactorDecision.Allowed(),
        _ => ReactorDecision.Allowed(),
    }),
});
```

### Transport security (§8b)

`ReactorServeOptions.Channel` takes an already-open channel, so the SDK cannot inspect how
it was opened. §8b's requirements used to live only in that property's doc comment — "its
connection MUST have been opened over `amqps://` with a trusted CA" — which meant a caller
who built a `ConnectionFactory` from an `amqp://` URI got a working reactor, no warning,
and signed-but-readable token decisions on the wire.

`ReactorConnections.CreateConnectionFactory` is the enforcing path:

| Parameter | Meaning |
|---|---|
| `amqpUri` | Must be `amqps://` (rules 1 and 5). Every other scheme is refused, and so is a URI that will not parse — a security check must fail closed on an input it cannot read. |
| `brokerCaCertificate` | The CA behind a privately issued broker certificate (rule 2 — the common in-cluster case). Added as an extra trust anchor; the OS store still applies. |
| `clientCertificate` | Mutual TLS (rule 3). A certificate without its private key is refused, rather than silently downgrading mTLS to ordinary TLS. |

`Ssl.AcceptablePolicyErrors` is pinned to `None` and `Ssl.ServerName` is taken from the URI
(a blank `ServerName` is how hostname verification quietly becomes nothing). There is no
verification-skip parameter under any name (rule 4), and no loopback exception — §8b rules
1 and 5 carry no host carve-out, and the AXIAM server is TLS-only.

`AxiamAmqpConsumer.StartAsync` enforces the same scheme rule for §8 consumers.

`ReactorServeOptions` still accepts any channel: enforcing at construction cannot
retroactively constrain a channel someone else opened.

### Binding handlers per event (§22.14)

The `switch` above is the shape every multi-event reactor grows, and its `_ =>` arm —
`ReactorDecision.Allowed()` — answers on behalf of code that never ran. That is the defect §22.10
rule 2 forbids the *runtime* from committing, relocated into your file where the rule does not reach
it: an operator who set `fail_closed` on the registration has it defeated there.

`ReactorHandlers` is §22.14's declarative form, and it uses the same attribute mechanism the §11
`[AxiamAccess]` helper already uses:

```csharp
public sealed class ClaimsReactor
{
    [OnReactorEvent(ReactorEvents.TokenPreIssue)]
    public Task<ReactorDecision> EnrichAsync(ReactorEvent e, CancellationToken ct) =>
        Task.FromResult(ReactorDecision.Mutated(new Dictionary<string, string>
        {
            ["ext.department"] = "engineering",
        }));

    [OnReactorEvent(ReactorEvents.LoginPostAuth)]
    public Task<ReactorDecision> ScreenAsync(ReactorEvent e, CancellationToken ct) =>
        Task.FromResult(Embargoed(e) ? ReactorDecision.Denied("embargoed region") : ReactorDecision.Allowed());
}

ReactorHandlers handlers = ReactorHandlers.Of(new ClaimsReactor());

await using ReactorServer server = await ReactorServer.ReactorServeAsync(new ReactorServeOptions
{
    Channel = channel,
    TenantId = tenantId,
    SigningKey = Sensitive<byte[]>.Wrap(subkey),
    ReactorId = reactorId,
    Handler = handlers.Handler(),
});
```

- **A misspelled event is refused when the attribute is read** — `ReactorHandlers` accepts only
  §22.5 registry names, which is also how it refuses the three hot-path operations §22.7 excludes:
  they are in no registry row. The message names the registry, never the exclusions.
- **An unbound event abstains** — the composed handler throws `UnboundReactorEventException`, and
  `ReactorServer` publishes **nothing** for a handler that threw, so the registration's
  `failure_policy` decides (§22.8) exactly as it decides a timeout. Never a synthesized `allow`.
- Binding the same event twice throws rather than silently overwriting, and `handlers.Events()`
  feeds `ReactorEvents.DefaultFailurePolicyFor` so you can see what an unreachable reactor costs
  before you go live.

Lambdas work too — `new ReactorHandlers().Bind(ReactorEvents.TokenPreIssue, fn)` — and both
spellings are governed by the same rules. It is pure sugar: `Handler()` returns exactly the
`ReactorHandler` `ReactorServer` already takes. It opens nothing, verifies nothing, signs nothing,
does not filter a patch, and a handler's own exception — thrown synchronously or carried on the
returned `Task` — reaches the runtime unchanged so nothing is published.

Register the reactor first — the queue it consumes is declared by the **server**, from a
`POST /api/v1/reactors` registration. See [`examples/Reactor`](examples/Reactor) for a runnable one
that enriches a token and screens a login.

### Both directions are signed

The server signs the event with the tenant's HKDF-derived AMQP subkey; this SDK signs the reply with
**the same** subkey. An unsigned or stale reply is not a weak reply — the server discards it as
though the reactor had never answered, and the registration's `failure_policy` takes over.

Everything is §8 v2 verbatim (same key derivation — `ReactorProtocol.DeriveTenantKey` if you hold the
master key rather than fetching the subkey from the management API — the same `ReplayGuard` this SDK
already uses for `AuthzRequest`/`AuditEventMessage`, the same constant-time HMAC-SHA256, the same
±300 s window applied in **both** directions, the same `key_version` floor of 2) with **one**
difference, and it is the one that costs an implementer a day if it is not stated: a reactor body is
signed with `hmac_signature` **present and set to `null`**, where `Amqp/Hmac.cs` *removes* it for
§8's own two message types. `Reactor/ReactorProtocol.cs` is the only place that rule lives, and it is
proven byte-for-byte against the server-generated §22.13 vectors — including the omission rules for
`reason`, `patch` and `require_mfa` (a reply serializing `"require_mfa": false` rather than omitting
it produces a different MAC).

Before your handler runs, the runtime rejects `key_version < 2`, verifies the MAC, checks freshness
in **both** directions, and checks the nonce. A runtime that hands an unverified payload to user code
has already lost.

### Five events, and what each may change

| Event | Mutable fields (the complete allow-list) | Default failure policy |
|---|---|---|
| `token.pre_issue` | **`ext.` namespace only** | `fail_open` |
| `login.post_auth` | — (veto, or `require_mfa`) | `fail_closed` |
| `user.pre_create` | `username`, `email`, `metadata.` namespace | `fail_closed` |
| `user.pre_update` | `username`, `email`, `metadata.` namespace | `fail_closed` |
| `grant.pre_assign` | — (veto only) | `fail_closed` |

An entry ending in `.` is a namespace prefix and needs at least one character after the dot:
`ext.department` and `ext.a.b.c` are in, and `ext.`, `ext`, `extra`, `external_id` and
`evil.ext.department` are not. No standard claim is reachable from `token.pre_issue`, because none of
them begins with `ext.` — a **correctly signed** reply setting `sub` is refused exactly as a forged
one is.

A registration naming no `failure_policy` inherits the **strictest** default among its events, in
either array order (`ReactorEvents.DefaultFailurePolicyFor`). A reactor registered for both
`token.pre_issue` and `login.post_auth` can veto a login, so it gets `fail_closed`.

### `authz.check` is not hookable, and never will be

`authz.check`, `authz.check_batch` and `token.introspect` are **absent** from
`ReactorEvents.Registry` and from every constant this SDK exposes — asserted by a test against the
reflected list, not documented by a comment. The reason is arithmetic, not policy: a reactor round
trip is milliseconds and the check path's budget is microseconds. Hooking it would not produce a
slower check, it would produce a different product.

This SDK also offers no interceptor, middleware hook or callback presenting itself as the reactor
equivalent for those operations. An application that needs external input on an authorization
decision writes a **deny grant**, which the engine evaluates in the hot path at hot-path cost.

### What the runtime will not do for you

- **It will not declare topology.** No `ExchangeDeclareAsync`, `QueueDeclareAsync` or
  `QueueBindAsync`, anywhere — asserted against the AMQP client's own recorded invocations. A reactor
  that can bind is a reactor that can bind itself to `*.token.pre_issue` and read another tenant's
  issuance events. `ReactorId` names your own queue and no other.
- **It will not synthesize an `Allowed()` for a handler that threw.** Throwing publishes *nothing*,
  and the operator's `failure_policy` decides what that costs. Answering `allow` on your behalf would
  defeat a `fail_closed` setting from inside the library.
- **It will not filter your patch.** A forbidden key goes on the wire as written and the server
  refuses the whole patch. Trimming it silently would leave you believing a field was set when it was
  dropped. (`ReactorEventSpec.PatchFieldAllowed` is there so you can check a key *before* writing the
  handler — never to filter one afterwards.)
- **It will not reply late.** When your handler returns after `ReactorEvent.TimeoutMs` has elapsed,
  the reply is abandoned — the server stopped listening, and publishing anyway only adds load.
  Consult `ReactorEvent.Remaining(now)` and shed load rather than push on.
- **It will not retry a reply (§16).** A correlation is single-use and a late reply is discarded; the
  recovery mechanism for an unanswered dispatch is the server-side `failure_policy`, not a resend.
  Connection recovery is `RabbitMQ.Client`'s, left on.

`DisposeAsync` is §18-deterministic: it cancels the consumer so no new delivery starts, drains what
is in flight up to `ShutdownGrace`, is idempotent, and leaves your channel and connection open — you
own those. §19 telemetry emits one `RequestStartEvent`/`RequestEndEvent` pair per dispatch with the
event name as the path template — a closed set of five values, so it cannot become a cardinality
bomb.

### Listeners

`mode: "listen"` is fire-and-forget observation: the server never waits and never reads a reply. Set
`Listener` instead of `Handler` — its delegate returns a plain `Task`, so a listener *cannot* publish
a reply rather than merely being told not to. Write it idempotently: a redelivery after a broker
hiccup is normal.

### Logging

The signing key is a credential and is wrapped in `Sensitive<byte[]>` — never logged at any level,
never in a reconnect diagnostic. The `payload`, `patch`, `reason` and `decision` are **not** secrets
and stay readable (a handler that cannot inspect the event cannot decide anything), but they are
tenant business data: this SDK never logs the payload, and neither should you at `Information` level.
The `nonce`, `correlation_id` and `hmac_signature` are not secrets and may be logged for correlation.

## OPAQUE (`Axiam.Sdk.Opaque`, CONTRACT.md §23)

`LoginOpaqueAsync` proves the password to the server without the password — or anything from
which it can be cheaply recovered — ever crossing the wire. The server stores a **registration
record** sealed under a tenant-wide oblivious PRF seed, and what travels is a blinded group
element and a MAC, neither useful without both.

```csharp
char[] password = ReadPassword();
try
{
    LoginResult result = await client.LoginOpaqueAsync("alice", password);
}
finally
{
    Array.Clear(password);
}
```

It takes the same arguments as `LoginAsync` and returns the same `LoginResult`, MFA branch
included, so switching a tenant to OPAQUE needs no change to how the result is handled. A
runnable example, including the fallback and the enrolment call, is in
[`examples/OpaqueLogin`](examples/OpaqueLogin).

Unlike the SRP-6a it replaces, there is no separate server-proof step and nothing has been
dropped: RFC 9807's AKE authenticates the server during the handshake, so opening `KE2` **is**
the proof that it holds the record. The old contract had to mandate an `M2` check in capitals
because skipping it kept only half the protocol; there is now nothing to skip.

### The protocol is not implemented here

CONTRACT.md §23.1 forbids an SDK from writing its own OPAQUE. SRP-6a was arithmetic every
language can express, which is why `Axiam.Sdk.Srp` existed at ~670 lines of modular
exponentiation. OPAQUE is not: it needs an oblivious PRF, `hash_to_curve`,
`expand_message_xmd`, an envelope construction and a three-message AKE, and eleven independent
implementations of that is eleven chances to be subtly and silently wrong in a way that still
interoperates until it does not.

`Axiam.Sdk.Opaque` therefore contains **no cryptography**. It is a P/Invoke binding to
`libaxiam_opaque_ffi`, the same implementation the AXIAM server links, plus the ownership
bookkeeping a binding has to get right.

### Installing

Nothing to add to your `.csproj` — .NET's own P/Invoke needs no package. What you do need is
the shared library: a Rust `cdylib` published as a per-platform asset on the
[axiam release page](https://github.com/ilpanich/axiam/releases), not a NuGet package, because
there is no cross-language registry to put it on.

Put it where the runtime probes for native libraries (alongside the application assembly is the
usual answer), or point at it:

```bash
export AXIAM_OPAQUE_LIBRARY=/opt/axiam/libaxiam_opaque_ffi.so
```

Ask before you need it:

```csharp
LoginResult result = client.OpaqueAvailable()
    ? await client.LoginOpaqueAsync(user, password)
    : await client.LoginAsync(user, new string(password));
```

Unlike the `SrpAvailable()` it replaces — hard-coded `true` on .NET because `BigInteger` and
BouncyCastle are always there — this can genuinely answer `false`. It reports rather than
throwing, so an application chooses the password path up front instead of discovering the gap
mid-exchange. It also *calls into* the library rather than merely finding it: a .NET P/Invoke
does not resolve until first use, so a probe that only located the file would report "present"
and then throw at login.

### What this buys, and what it does not

OPAQUE closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh sees every plaintext
  password today; under OPAQUE it sees `KE1` and `KE3`;
- an accidental request-body log, a heap dump or a crash reporter can no longer capture a
  plaintext password, because the server never has one;
- **a stolen record database is not offline-crackable on its own.** This is the substantive
  gain over SRP: cracking a record also requires the tenant's OPRF seed, which is AES-256-GCM
  encrypted at rest under a key the database does not hold.

It does **not** protect against a compromised AXIAM server, and this SDK does not claim it
does.

### Tenant policy, and the errors that are not credential failures

`opaque_mode` is an organization baseline a tenant may tighten:

| mode | `LoginAsync` | `LoginOpaqueAsync` |
|---|---|---|
| `disabled` (default) | works | `NetworkError` — the endpoint answers `404` |
| `optional` | works | works |
| `required` | `AuthzError` | works |

Which exception you get is most of what this SDK owns on this path:

| condition | exception | why |
|---|---|---|
| tenant has OPAQUE disabled | `NetworkError` | a property of the tenant, not of any user — fall back to `LoginAsync` |
| shared library absent | `NetworkError` | a deployment fact, raised before any request is sent |
| server named a KSF this build cannot perform | `NetworkError` | a configuration problem; substituting one would surface as a wrong password |
| `/start` response missing `ke2` | `NetworkError` | malformed response |
| envelope did not open / `KE2` did not verify | `AuthError`, or whatever the password login returns under `optional` | the **whole** of the credential check — see below |
| tenant refuses password login (`LoginAsync`) | `AuthzError` | the credentials were never examined |

That `AuthError` covers both halves of the mutual authentication: a wrong password, an account
that does not exist, an account with no registration record, and a server that does not hold
the record are indistinguishable by design. **Nothing is sent to `login/finish` in that case**
(§23.4 rule 7), and what happens next depends only on the `mode` the `login/start` response
carried — the tenant's `opaque_mode`:

- `optional` — `LoginOpaqueAsync` retries over `LoginAsync` with the same credentials before
  reporting anything, and hands you that call's outcome: its success on success, its error on
  failure. Under `optional` an account with no record is the ordinary case rather than an
  error — every account has none the moment an operator enables OPAQUE, and acquires one only
  as it next sets a password — so treating the failed exchange as final would lock out every
  user of a tenant mid-migration, the state `optional` exists to serve.
- `required`, an absent `mode` (a server older than contract 1.29) and any value this SDK does
  not recognise — the failure is `AuthError`, the exchange is over, and nothing is retried. Do
  not retry over `LoginAsync` yourself: that hands the plaintext to an endpoint that just
  failed to prove it holds the record, and `required` answers `403 opaque_required` for every
  principal anyway.

`mode` is **not** downgrade protection and this SDK does not present it as such: a hostile
server that wanted the plaintext could answer `404` and get a fallback whatever it puts there.
What closes that is the server refusing `/auth/login` under `required`, before it examines any
credential.

`required` refuses **every** principal in the tenant, not only the enrolled ones. Splitting the
response on whether an account has a record would turn `/auth/login` into an enumeration oracle
costing one junk password per name. It also means `required` locks out anyone not yet enrolled:
a record needs the plaintext password, and a stored Argon2id hash is not invertible, so nobody
can be enrolled retroactively. Operators turn it on last, after a password-reset campaign.

### Enrolment

The server cannot build a registration record, so any request that **sets** a password has to
carry one. `OpaqueEnrollmentAsync` produces the `opaque` object for `POST /api/v1/users`,
`/auth/password/change`, `/auth/reset/confirm` and `/admin/bootstrap`:

```csharp
OpaqueEnrollment enrolment = await client.OpaqueEnrollmentAsync(newPassword);
body["opaque"] = enrolment.ToWire();
```

Note the parameters that are gone. There is no `identity`: the SRP version required the
account's **username**, an email there produced a verifier no login could ever satisfy — and
renaming a user invalidated their verifier outright. A record binds to a credential identifier
the server chooses, so neither is true any more. There is no `group` or `SrpKdfParams` either:
those come from the `register/start` response, so a caller cannot pick a cost the server will
not honour.

Unlike `SrpEnrollment` this is asynchronous and performs network I/O — one `register/start`
round trip. The envelope is sealed under the server's oblivious PRF, so there is no offline
computation that produces a valid record.

### Cost

`LoginOpaqueAsync` runs the tenant's key-stretching function: Argon2id at 19 MiB and t=2 by
default, which is tens to hundreds of milliseconds of CPU plus that memory, per login attempt.
That cost is the point — it is what makes a stolen record expensive to attack even by someone
holding the OPRF seed. It runs on the thread pool rather than the caller's thread, but it is
still CPU that has to come from somewhere: size your pool and request timeouts accordingly. It
is not a cost `LoginAsync` has.

### Cryptographic parameters

The ciphersuite is `OPAQUE-3DH` over **ristretto255** with **SHA-512**, HKDF-SHA-512 and
HMAC-SHA-512, fixed AXIAM-wide. It is not negotiated and not read from the server: a client
that accepted a suite from the endpoint it is authenticating would be accepting a downgrade.

The key-stretching function *is* the server's to name, per exchange, and is honoured as given
rather than cached or defaulted — a credential enrolled under one cost keeps working after a
tenant raises its policy. `argon2id` and `scrypt` are accepted; anything else is refused rather
than substituted. Costs outside the bands this SDK will act on (`memory_kib` 8 MiB–1 GiB,
`iterations` 1–10, `parallelism` 1–16, `log_n` 14–20, `r`/`p` 1–16) are refused too: a server
is trusted to name its own policy, not to name a cost that would wedge every device an account
owns.

### Zeroization

`LoginOpaqueAsync` and `OpaqueEnrollmentAsync` take the password as a `char[]` so the caller
can clear it, and clear every copy they make of it — including the UTF-8 bytes handed across
the ABI. They cannot clear the caller's array; do that yourself, in a `finally`. If your
password arrives as a `string` (from a JSON body, say), it is already immutable and already
copied; the `char[]` signature is honest about where this SDK's reach ends rather than implying
a guarantee it cannot keep.

The password crosses the ABI as **UTF-8**, explicitly, never through default string
marshalling. A password that encoded differently under a different platform default would
derive a randomized password no AXIAM server agrees with, and would surface as a wrong password
on that machine only.

## WebAuthn / passkeys (`Axiam.Sdk.Webauthn`, CONTRACT.md §24)

Six wire operations, two ceremonies, and one thing this SDK deliberately does not do.

```csharp
// Enrolment — requires a session (§24.1), refused client-side without one.
WebauthnChallenge challenge = await client.WebauthnRegisterStartAsync();
WebauthnCredential credential = await client.WebauthnRegisterFinishAsync(
    challenge.StateToken, "Alice's laptop", platformResponseJson);   // verbatim

// Sign-in with no username at all — the authenticator picks the account.
WebauthnChallenge signIn = await client.WebauthnDiscoverableStartAsync();
WebauthnLoginResult result = await client.WebauthnDiscoverableFinishAsync(
    signIn.StateToken, assertionJson);
```

**The server chooses every option and verifies every response; this SDK passes both through
byte-for-byte** (§24.0). `WebauthnChallenge.Challenge` is a raw `JsonElement`, not a modelled type:
no defaulting, no validation-that-rejects, no re-encoding. On the way back the `*Finish` body is
assembled as **text**, splicing the caller's response string in unmodified — deserializing and
re-serializing it would hand the server a byte sequence the authenticator never signed.

### The browser half, via the §24.6a JSON bridge

.NET has no authenticator, so the ceremony runs wherever the user is. `RequestJson` is the string
that half needs:

```csharp
// ASP.NET Core relying party
app.MapPost("/passkeys/start", async (AxiamClient client) =>
{
    WebauthnChallenge challenge = await client.WebauthnRegisterStartAsync();
    // §24.6a rule 1: the wire JSON, unparsed and unreassembled.
    return Results.Ok(new { challenge.RequestJson, stateToken = challenge.StateToken.Expose() });
});
```

```javascript
// Browser
const options = PublicKeyCredential.parseCreationOptionsFromJSON(requestJson);
const credential = await navigator.credentials.create({ publicKey: options });
await fetch('/passkeys/finish', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ stateToken, response: credential.toJSON() }),  // verbatim
});
```

`RequestJson` is the inner options object — the `publicKey` wrapper belongs to the DOM's
`CredentialCreationOptions`, and the platform JSON APIs do not want it. A MAUI app relaying Android's
`registrationResponseJson`, or an Uno app relaying a `DOMException` name, uses the same two seams.

Passing something that is not JSON, or is not a JSON object, raises `AuthError` client-side with no
wire call: the SDK will not POST a body it already knows the server cannot verify.

### The two authentication ceremonies are different flows (§24.2)

`WebauthnAuthenticateStartAsync`/`FinishAsync` is a **second factor** — it continues a `LoginAsync`
that answered `MfaRequired` with `"webauthn"` among its methods, and the challenge token names the
user so the server can send an `allowCredentials` list. `WebauthnDiscoverableStartAsync`/`FinishAsync`
is a **primary factor**: nothing precedes it, `allowCredentials` is empty, and the assertion itself
identifies the user. They are not one operation with an optional token — merging them reproduces a
bug the server already fixed, which is why the token is a required argument on one and absent from
the other.

One difference a reactor author will ask about: `discoverable/finish` fires the `login.post_auth`
hook event (§22.5) and `authenticate/finish` does not. The latter continues a login already gated at
its password step; the former has no such step to have been gated at.

### Saying something useful when a ceremony fails (§24.6b rule 5)

```csharp
WebauthnFailure outcome = WebauthnFailures.Classify(domExceptionName);
string copy = outcome.Message();
```

`AlreadyRegistered` is the exclusion list doing its job, and the only classification whose remedy is
"use a different device" rather than "try again". `Cancelled` covers **both** an explicit refusal and
a silent timeout — the spec deliberately refuses to distinguish them, because telling a website which
one happened leaks whether an authenticator was present — so its copy does not accuse anyone of
cancelling.

### Two error rows that are not the §2 defaults (§24.4)

- A **403 from `register/finish`** is the tenant's *attestation policy* rejecting this particular
  authenticator. The server's message is the only place that says which one would be accepted, so it
  is lifted into the `AuthzError`'s message rather than discarded. Show it.
- A **503 from `register/start`** means the policy needs FIDO metadata the server cannot reach. That
  is a configuration state, not a transient one, and it is **not retried** — the second documented
  exception to §16 after §20's.

Session cookies: as of contract 1.28 both `*FinishAsync` authentication calls set the `axiam_access`
/ `axiam_refresh` / `axiam_csrf` triple alongside the token body, so a completed ceremony leaves the
client signed in for every cookie-driven call that follows (§24.3).

Worked end to end in [`examples/WebauthnPasskeys`](examples/WebauthnPasskeys).

## Account lifecycle and MFA enrolment (`Axiam.Sdk.Account`, CONTRACT.md §25)

Nine operations covering the things a user does to their own account — none of which is
administration, and all of which were previously reachable only by hand-rolling HTTP.

```csharp
LoginResult result = await client.LoginAsync("alice@example.com", password);

if (result.MfaSetupRequired)
{
    // The third outcome. The tenant requires MFA, this account has none, and the
    // server handed back a setup token to finish with. There is no session yet —
    // the token IS the credential.
    Sensitive<string> setupToken = result.SetupToken!;
    MfaEnrollment enrollment = await client.MfaSetupEnrollAsync(setupToken);
    RenderQr(enrollment.TotpUri.Expose());
    await client.MfaSetupConfirmAsync(setupToken, code);    // completes the LOGIN
}
```

`LoginResult` gained two components with defaults rather than changing shape, so every pre-1.28
construction still compiles and still reads `false`. **Handle the new outcome anyway.** A tenant that
turns on required MFA will start returning it, and a client that only branches on `MfaRequired`
reports a successful login that has no session.

`MfaSetupConfirmAsync` adopts credentials exactly as `LoginAsync` does, because it *is* the
completion of a login (§25.2 rule 2). `MfaEnrollAsync`/`MfaConfirmAsync` are the voluntary pair, from
inside an existing session, and they do **not** clear the §17 decision memo — the subject has not
changed, and discarding a warm memo on an unrelated profile action costs a round trip on every check
that follows.

Both halves of an `MfaEnrollment` are `Sensitive<string>`, and the second one matters: the
`otpauth://` URI *contains* the secret (§25.3). Wrapping the bare secret and then logging the URI
leaks the same bytes.

### Password reset, and the two things it will not tell you

```csharp
await client.RequestPasswordResetAsync(new PasswordResetRequest { Email = "alice@example.com" });
// returns a bare Task, whether or not that address has an account

PasswordResetContext context = await client.PasswordResetContextAsync(Sensitive<string>.Wrap(token));
if (context.Opaque is not null)
{
    // This tenant runs §23. Build a registration record from these parameters;
    // a plaintext password would be refused, and refused late (§25.4 rule 1).
}
await client.ConfirmPasswordResetAsync(new PasswordResetConfirmation
{
    // Sensitive<T>.Wrap is public for exactly this: the token arrives from a mail link as
    // a bare string, and wrapping a value can never leak it — only Expose() can.
    Token = Sensitive<string>.Wrap(token), NewPassword = Sensitive<string>.Wrap(newPassword),
    TenantId = tenantId,
});
```

`RequestPasswordResetAsync` returns nothing and throws nothing on an unknown address, and this SDK
exposes no way to tell the two cases apart. That is not an omission to improve on: a client that
surfaced a "no such user" state — even one inferred from timing — would turn the endpoint into the
account-enumeration oracle its uniform response exists to prevent. Likewise a `404` from
`PasswordResetContextAsync` means unknown, expired **or** already-consumed, and the SDK does not
distinguish them either (§25.4 rule 3).

`VerifyEmailAsync` and `ResendVerificationAsync` are unauthenticated — a user whose address is
unverified may have no session at all — and carry the tenant as a **body** field, since §12.1 rule 2's
`?tenant_id=` convention is scoped to the `/oauth2` endpoints.

Worked end to end in [`examples/AccountLifecycle`](examples/AccountLifecycle).

## Pushed Authorization Requests (CONTRACT.md §26, RFC 9126)

PAR moves the authorization request off the browser. Instead of putting `scope`, `redirect_uri`,
`state` and the PKCE challenge into a URL the user agent carries, the client POSTs them straight to
AXIAM over an authenticated back channel and puts an opaque `request_uri` in the redirect.

```csharp
OidcConfiguration config = await client.OidcDiscoverAsync();
if (string.IsNullOrEmpty(config.PushedAuthorizationRequestEndpoint))
{
    // §26 is optional; fall back to the plain OidcBegin redirect.
}

AuthorizationRequest begun = client.OidcBegin(
    config, new OidcBeginParams { RedirectUri = redirectUri, Scope = "openid profile" });

PushedAuthorizationRequest pushed = await client.OidcParAsync(new OidcParParams
{
    Request = begun, RedirectUri = redirectUri, Configuration = config, Scope = "openid profile",
});

return Results.Redirect(pushed.Url);   // exactly ?client_id=…&request_uri=…
```

Three things worth knowing:

- **The server answers `201`,** not `200` — RFC 9126 §2.2 specifies *Created*. A success predicate
  written `== 200` treats every successful push as a failure.
- **The redirect URL carries exactly two parameters.** The server refuses a request that mixes a
  `request_uri` with inline authorization parameters rather than merging them; merging is where
  parameter confusion lives (§26.2 rule 2). Any query the discovered `AuthorizationEndpoint` already
  carried is dropped.
- **`OidcBegin` still owns `State`, `Nonce` and the PKCE pair.** There is no second generator (§26.2
  rule 1), and `PushedAuthorizationRequest` carries all three straight through to the exchange.

The push is **not retried** on a 5xx or a transport failure: it is a POST that creates server state,
so it falls outside §16.2's read-only eligibility exactly as `OidcExchangeAsync` does. The safe
recovery is a fresh push, which costs one round trip and cannot double-consume anything. The
`RequestUri` is `Sensitive<string>` because between the push and the redirect it is a bearer handle to
a fully-formed authorization request (§26.5).

A **FAPI 2.0 client has no alternative**: `profile: "fapi2"` refuses a registration that does not set
`require_par`, so such a client cannot authorize any other way (§21.1).

Worked end to end in [`examples/ParLogin`](examples/ParLogin).

## Grpc.Tools exception

The C# SDK is the **one documented exception** to the `buf` codegen pipeline every other
AXIAM SDK uses. Rust, TypeScript, Python, Java, PHP and Go all run `buf generate` to produce
gRPC stubs from `proto/axiam/v1/`. The C# SDK uses **`Grpc.Tools` MSBuild codegen** instead:
the `.proto` files are included via `<Protobuf Include="../proto/axiam/v1/*.proto" />` in
`Axiam.Sdk.csproj` and stubs are generated into `obj/` at build time by the `Grpc.Tools`
package, not by buf. This repository therefore carries no `buf.yaml`/`buf.gen.yaml`.

This exception is intentional and approved (D-01). The C# SDK still tracks the same
`proto/axiam/v1/` definitions as the buf pipeline; only the codegen toolchain differs.

## Status

`Axiam.Sdk` (REST + gRPC + AMQP + the §22 reactor runtime + `Sensitive` + JWKS) and `Axiam.Sdk.AspNetCore`
(middleware + DI + policy authorization) are both fully implemented and tested. See
the Quickstart above and [`examples/`](examples/) for runnable code.

## Client quality-of-life (CONTRACT.md §16–§19)

### Retry policy (§16)

Read-only authorization checks retry transient failures under the contract's normative table:
**3 attempts** (1 initial + 2 retries), 200 ms base, 5 s cap, **full jitter** (uniform over
`[0, backoff]`), and `Retry-After` honored as a **floor**.

> **This is new behaviour.** `MaxRetryAttempts`, `RetryBaseDelay` and `RetryMaxDelay` have
> existed on `AxiamClientOptions` since the beginning — defaulted, documented, and asserted in
> tests — but their own doc comment said they were "not yet wired into any call path", and
> nothing read them. **The SDK performed no read-only retries at all.** They are wired now.

Only failures that could plausibly succeed on a second attempt are retried: transport errors,
`408`, `429`, `5xx`. A `401` or `403` is an answer, not a transport failure, and surfaces after
exactly one attempt. Nothing that changes server state is ever retried.

```csharp
// Turn it off if you own your own retry layer — you know your deadline, this SDK doesn't.
var options = new AxiamClientOptions { BaseUrl = baseUrl, TenantId = "acme", RetryEnabled = false };
```

**Values above the contract's are clamped down, not honored.** §16.1 permits an SDK to *lower*
the attempt cap or disable retry outright, never to raise it — a caller who could raise it turns
one client into the thundering herd the policy exists to prevent. Setting `MaxRetryAttempts = 10`
gets you 3; setting 1 gets you 1. The same applies to `RetryBaseDelay` and `RetryMaxDelay`.

### Deterministic shutdown (§18)

`Dispose()` releases the client's local resources. It is idempotent — `Interlocked` means even a
concurrent double-dispose does the work once — and any call afterwards throws
`ObjectDisposedException` rather than silently reconnecting. That is the .NET-idiomatic answer,
and it is what a caller's existing handlers already expect.

**`Dispose()` does not log out.** It never reaches the network. The server-side session
deliberately outlives the client object — that is what lets a process restart and resume — so a
`Dispose()` that logged out would silently end every user's session on each deploy. Call
`LogoutAsync()` first if ending the session is what you want.

### Telemetry hooks (§19)

Wire metrics without this package depending on any metrics library:

```csharp
var options = new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = "acme",
    TelemetryHook = e =>
    {
        switch (e)
        {
            case RequestEndEvent end:
                histogram.Record(end.Duration.TotalMilliseconds, /* labels */);
                break;
            case RetryEvent retry:
                counter.Add(1, /* labels */);
                break;
        }
    },
};
```

- **A hook that throws cannot fail the operation that fired it.** One exception:
  `OperationCanceledException` is re-thrown rather than swallowed, since hiding a cancellation
  the caller asked for is a correctness concern rather than a metrics one.
- **No event payload can carry a token.** The event hierarchy is closed — `TelemetryEvent`'s
  constructor is `private protected`, so no type outside the assembly can derive from it — with
  fixed property lists.
- **Path templates, not URLs**, so a metric label cannot become a cardinality bomb.

One `RequestStartEvent`/`RequestEndEvent` pair is emitted **per attempt**, so you can count real
wire calls.

### Decision memo (§17) — opt-in, off by default

An optional TTL-bounded cache for authorization checks. **Disabled by default**, because §11.2
rule 6's ban on caching authorization decisions is still the default behaviour.

```csharp
var options = new AxiamClientOptions
{
    BaseUrl = baseUrl,
    TenantId = "acme",
    DecisionMemoTtl = TimeSpan.FromSeconds(5), // TimeSpan.Zero (the default) = off
};
```

**What you are accepting.** The staleness bound is the TTL, in *both* directions: a grant
revoked on the server can still read as allowed for up to the TTL, and a grant just added can
still read as denied for up to the TTL.

> **Reads-your-own-writes is not guaranteed.** An admin UI that grants a role and immediately
> re-checks is the case that breaks, and it breaks silently. If that is your workload, leave this
> off.

The TTL is clamped to 5 seconds rather than rejected. Allows and denies are memoized identically
— asymmetric caching would leak which outcome occurred through latency. Failures are never
memoized: caching a transport error as a deny would turn a blip into a TTL-long outage. The memo
is cleared on `LoginAsync`, `VerifyMfaAsync`, `RefreshAsync` and `LogoutAsync`, since entries are
keyed by subject rather than by session. It is thread-safe.
