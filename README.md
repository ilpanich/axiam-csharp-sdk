# Axiam.Sdk (C#)

[![CI](https://github.com/ilpanich/axiam-csharp-sdk/actions/workflows/sdk-ci-csharp.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-csharp-sdk/actions/workflows/sdk-ci-csharp.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-csharp-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-csharp-sdk?branch=main)
[![NuGet Axiam.Sdk](https://img.shields.io/nuget/v/Axiam.Sdk.svg?label=NuGet%3A%20Axiam.Sdk)](https://www.nuget.org/packages/Axiam.Sdk)
[![NuGet Axiam.Sdk.AspNetCore](https://img.shields.io/nuget/v/Axiam.Sdk.AspNetCore.svg?label=NuGet%3A%20Axiam.Sdk.AspNetCore)](https://www.nuget.org/packages/Axiam.Sdk.AspNetCore)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official C# client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **NuGet packages:** [`Axiam.Sdk`](https://www.nuget.org/packages/Axiam.Sdk) (core) and
  [`Axiam.Sdk.AspNetCore`](https://www.nuget.org/packages/Axiam.Sdk.AspNetCore) (ASP.NET Core middleware)
- **Source:** [github.com/ilpanich/axiam-csharp-sdk](https://github.com/ilpanich/axiam-csharp-sdk)
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1–§12 (including §6.1 mTLS client certificates, the
§1.1 gRPC-only `get_user_info` operation, contract 1.3, and the §12 OIDC/SSO
relying-party helpers, contract 1.4).

See [`CONTRACT.md`](CONTRACT.md) for the full cross-language behavioral contract.

### §1–§11 conformance checklist

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
| §11 | Declarative `[AxiamAccess(action, resource)]` authorization attribute with scope + route-param resolution; `require_auth`/`require_role` as framework-native `[Authorize]`/`[Authorize(Roles = ...)]` | `Axiam.Sdk.AspNetCore/AxiamAccessAttribute.cs`, `AxiamRequirement.cs`, `AxiamPolicyHandler.cs`/`AxiamPolicyProvider.cs` |
| §12 | OIDC/SSO relying-party helpers: `OidcDiscoverAsync`/`OidcBegin`/`OidcExchangeAsync`/`OidcRefreshAsync`/`LoginClientCredentialsAsync`/`IntrospectAsync`/`RevokeAsync`/`SsoStartAsync`/`SsoCompleteAsync`; `MapAxiamOidcLogin` ASP.NET Core glue | `AxiamClient.Oidc.cs`, `Auth/Oidc/*.cs`, `Axiam.Sdk.AspNetCore/OidcLoginEndpoints.cs` |

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

`Axiam.Sdk` (REST + gRPC + AMQP + `Sensitive` + JWKS) and `Axiam.Sdk.AspNetCore`
(middleware + DI + policy authorization) are both fully implemented and tested. See
the Quickstart above and [`examples/`](examples/) for runnable code.
