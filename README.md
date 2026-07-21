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

This SDK conforms to CONTRACT.md §1–§11 (including §6.1 mTLS client certificates and the
§1.1 gRPC-only `get_user_info` operation, contract 1.3).

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
