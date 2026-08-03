# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **BREAKING (acceptance tightened).** Align local token verification with the new
  normative CONTRACT.md §10.1 "minimum local-verification set". Two of the seven rules
  were not enforced by `JwksVerifier.VerifyAsync`:
  - **`exp` is now REQUIRED.** The old check read
    `if (claims.TryGetProperty("exp", …) && expEl.TryGetInt64(…) && expired)` — so a
    token carrying **no** `exp` at all failed the first conjunct and was admitted, and a
    token whose `exp` was a JSON *string* failed the second and was also admitted. Both
    are permanent credentials. This is the `SEC-080` defect verbatim, and it appeared
    twice: `AxiamAuthMiddleware` carried a "defense-in-depth" `exp` re-check written to
    the same shape, so it re-derived the same blind spot instead of catching it. That
    duplicate check has been removed — the guard now routes through the single
    authoritative implementation rather than two subsets that each look complete alone.
  - **`nbf` is now honoured.** The claim was never read, so a token was accepted before
    its validity window opened.
  - **The `X-Tenant-ID` request header could OVERRIDE the configured tenant.**
    `AxiamAuthMiddleware` read `X-Tenant-ID` first and only fell back to
    `AxiamOptions.DefaultTenantId`, then verified the token against *that*. Because the
    header is attacker-controlled, presenting a token for tenant B alongside
    `X-Tenant-ID: B` compared the token against itself — a vacuous check that admitted
    any tenant's token to an app configured for a different one, and then injected the
    attacker's tenant into `HttpContext.User`. §10.1 rule 4 requires the assertion be
    made against the **configured** tenant. The header now only *narrows*: when present
    it must agree with the verified claim, and it can never select which tenant is
    expected.

  Tokens minted by the AXIAM server are unaffected — they always carry `exp` and never a
  future `nbf`. A guard fed tokens from **another signer sharing the organization-wide
  JWKS** — or an application relying on `X-Tenant-ID` to serve multiple tenants from one
  configured client — may start rejecting what it previously accepted. That is the intent.

### Added

- Add `AxiamOptions.ExpectedIssuer` / `AxiamOptions.ExpectedAudience` (and the
  corresponding `AxiamClientOptions` properties, plus optional `JwksVerifier`
  constructor parameters) — the CONTRACT.md §10.1 rule 5/rule 6 checks. Both are
  **conditional and default to unset**: with no expectation configured no check is
  performed, and once configured a mismatching — or absent — claim is rejected. No
  issuer or audience is hardcoded anywhere in this SDK; an app guarding a user-facing
  resource server should generally expect `axiam:user`. `aud` accepts both the
  single-string and array forms RFC 7519 permits.
- Add `JwksVerifier.ClockSkewLeeway` — the named, bounded 60-second clock-skew constant
  applied to the `exp`/`nbf` checks (§10.1 rule 7). It is a `static readonly` constant
  and is deliberately not operator-configurable.
- Add the complete §10.1 required negative-test set
  (`tests/Axiam.Sdk.Tests/Contract101LocalVerificationTests.cs`, 26 cases): expired; no
  `exp`; non-numeric `exp`; numeric-*string* `exp`; null `exp`; future `nbf`; malformed
  `nbf`; different tenant; no `tenant_id`; no configured tenant; `alg: none`; a real
  HS256-signed token bearing an EdDSA key id; and issuer/audience mismatch and
  absent-claim cases. Two of them are additionally asserted end to end through the real
  ASP.NET Core pipeline in `AspNetCoreMiddlewareTests`, proving the guard routes through
  the full set rather than a subset of its own.
- Add webhook signature verifier `Axiam.Sdk.Webhooks.AxiamWebhooks.Verify` (CONTRACT.md §13, T-145)

### Changed

- Re-sync the vendored `CONTRACT.md` with the new normative §10.1.

### Notes

- This SDK uses **no JWT library** — there is no `System.IdentityModel.Tokens.Jwt`,
  `JwtSecurityTokenHandler`, or `TokenValidationParameters` in its dependency graph
  (.NET ships no Ed25519 primitive, so JOSE processing is hand-rolled over
  BouncyCastle). No library default was relied on, and none was changed; every §10.1
  rule is enforced explicitly in `JwksVerifier`.

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Added

- Add OIDC/SSO relying-party helpers (CONTRACT.md §12)

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Re-sync vendored CONTRACT.md to contract 1.5
- Bump the minor-patch group with 1 update
- Bump actions/checkout from 7.0.0 to 7.0.1

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Bump Microsoft.AspNetCore.Mvc.Testing and 4 others (#17)
- Bump actions/setup-dotnet from 5.4.0 to 6.0.0 (#16)
- Bump coverlet.collector from 6.0.4 to 10.0.1 (#18)
- Bump xunit.runner.visualstudio from 2.8.2 to 3.1.5 (#19)
- Ratchet coverage floor 92% -> 94% (#21)

## [1.0.0-alpha16] - 2026-07-22

### Changed

- Implement gRPC GetUserInfoAsync (CONTRACT §1.1, contract 1.3)
- Sync userinfo.proto + CONTRACT.md (contract 1.3)

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha12.

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Supply organization context for login/refresh (CONTRACT §5.1) (#15)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

## [Unreleased]

### Added

- gRPC `GetUserInfoAsync` (CONTRACT.md §1.1, contract 1.3). New
  `Grpc.AxiamGrpcAuthzClient.GetUserInfoAsync(CancellationToken)` calls the new
  `axiam.v1.UserInfoService/GetUserInfo` RPC on the SDK's existing gRPC channel — the
  low-latency counterpart of the server's REST `GET /oauth2/userinfo`. The request is
  empty; identity is derived server-side from the bearer token. It reuses the exact same
  `authorization`/`x-tenant-id` metadata (§5) and single-flight `UNAUTHENTICATED`
  refresh-and-retry guard (§9) as `CheckAccessAsync`, raises `AuthError` client-side
  without a wire call when there is no active session (§1.1.3), and returns a typed
  `Grpc.UserInfo { Sub, TenantId, OrgId, Email?, PreferredUsername? }` — `Email` populated
  only with the `email` scope and `PreferredUsername` only with the `profile` scope
  (absent optionals surface as `null`). Vendored `proto/axiam/v1/userinfo.proto` +
  re-synced `CONTRACT.md` (contract 1.3).
- Client-certificate / mutual-TLS (mTLS) support (CONTRACT.md §6.1). New
  `AxiamClientOptions.ClientCertificatePem` / `ClientKeyPem` (PEM certificate chain +
  PEM PKCS#8/PKCS#1 private key) configure an optional X.509 client identity that is
  applied to **both** the REST and gRPC transports of the same `AxiamClient`. The
  matching `Axiam.Sdk.AspNetCore.AxiamOptions.ClientCertificatePem` / `ClientKeyPem`
  flow through to the shared client. mTLS is opt-in; supplying exactly one of the
  cert/key pair throws `ArgumentException` at construction. Strict server verification
  is unchanged — the client-cert path is separate from §6's server-trust handling and
  adds no TLS-bypass surface. The private key is treated as secret material (§7).

### Added

- `Axiam.Sdk.AspNetCore`: `AxiamAccessAttribute` (`[AxiamAccess(action, resource)]`) —
  the CONTRACT.md §11 declarative authorization helper. Sugar over the existing
  `[Authorize(Policy = "resource:action")]` mechanism, with `Scope` and
  `ResourceRouteParam` properties. The legacy `"resource:action"` policy-string form
  remains fully supported side by side.
- `AxiamPolicyHandler`/`AxiamAuthorizationMiddlewareResultHandler`: a missing or
  non-UUID resource route value now returns `400 invalid_request` instead of silently
  falling back to `Guid.Empty`; a transport failure while calling the authz endpoint
  now returns `503 authz_unavailable` (fail-closed) instead of surfacing an unhandled
  exception. A server-issued `403`/`409` on the check call maps to `403
  authorization_denied`, and a server `401` (the app's own service session failing to
  authenticate) fails closed to `503 authz_unavailable` — neither escapes as an
  unhandled `500`.
- SDK now conforms to CONTRACT.md §1–§11 (previously §1–§10).
- OIDC / SSO relying-party helpers (CONTRACT.md §12, contract 1.4) — "Login with
  AXIAM" (authorization-code + PKCE), service-account `client_credentials` login,
  token introspection/revocation, and upstream-IdP federation SSO. The nine
  canonical operations ship directly on `AxiamClient` (no separate client type):
  `OidcDiscoverAsync`, `OidcBegin` (no `Async` suffix — pure local computation,
  no network I/O), `OidcExchangeAsync`, `OidcRefreshAsync`,
  `LoginClientCredentialsAsync`, `IntrospectAsync`, `RevokeAsync`,
  `SsoStartAsync`, `SsoCompleteAsync`. New `Auth/Oidc/` types:
  `OidcConfiguration`, `AuthorizationRequest`, `OidcTokenSet`, `IdTokenClaims`,
  `IntrospectionResult`, `SsoStartResult`/`SsoCompleteResult`, and the optional
  `IOidcStateStore`/`MemoryOidcStateStore` (10-minute TTL, single-use
  `ConsumeAsync`). `Axiam.Sdk.AspNetCore` adds `MapAxiamOidcLogin` — minimal-API
  login-redirect + callback endpoints wired into the existing DI pipeline (a
  `MemoryOidcStateStore` is registered by `AddAxiam`/`AddAxiamAspNetCore` unless
  the app registers its own `IOidcStateStore` first). ID-token validation
  (§12.4) reuses the existing JWKS verifier (`JwksVerifier`, extended not
  forked) and enforces `alg=EdDSA`, signature, `iss`, `aud`/`azp`,
  `exp`/`iat`/`nbf` (±60s skew), and `nonce`, raising `AuthError` with a stable
  `Reason` (`invalid_alg`, `unknown_kid`, `invalid_signature`,
  `invalid_issuer`, `invalid_audience`, `token_expired`, `nonce_mismatch`) and
  discarding the whole token set on any failure. New `OAuthProtocolError` — a
  sub-type of `AuthError` (existing `catch (AuthError)` code keeps working
  unchanged) — surfaces an RFC 6749 `OAuth2ErrorResponse` with `Error`/
  `ErrorDescription`. `Sensitive<T>` gained a public `Expose()` accessor and a
  public `Wrap()` factory: CONTRACT.md §7 said "the raw token string MUST NOT
  be exposed via any public getter API," written when every token lived only
  in the httpOnly cookie jar; §12 delivers `access_token`/`refresh_token`/
  `id_token` directly in the `/oauth2/token` response body, so the caller MUST
  be able to read them back out — `ToString()`/JSON serialization still always
  redact. `LoginClientCredentialsParams.AdoptAsCredential` (the §12.1 "adopt as
  the client's own bearer credential" MAY) is intentionally NOT implemented in
  this port — it throws `NotSupportedException` if set. `AxiamHttpMessageHandler`
  additionally exempts `/oauth2/token`, `/oauth2/introspect`, and
  `/oauth2/revoke` from the reactive §9 refresh-and-retry (a client-credential
  `401` is not a session expiry). No new runtime dependency — PKCE/CSPRNG use
  only `System.Security.Cryptography`. New `examples/AspNetCoreSample`
  `MapAxiamOidcLogin` wiring and `examples/Quickstart`
  `LoginClientCredentialsAsync`/`IntrospectAsync`/`RevokeAsync` walkthrough.
- SDK now conforms to CONTRACT.md §1–§12 (previously §1–§11).

## [1.0.0-alpha] - 2026-07-15

First alpha release of the official .NET client SDK for AXIAM. This is an early,
pre-production preview published to NuGet for evaluation and feedback — the
public API may still change before the beta and stable releases.

### Added

- `Axiam.Sdk` — REST client covering the AXIAM API surface (authentication,
  authorization checks, tenant/user/role/resource management) plus a gRPC
  client for low-latency authorization checks.
- `Axiam.Sdk.AspNetCore` — ASP.NET Core integration for guarding application
  endpoints.
- Strict TLS by default with no certificate-verification bypass surface.
- Deterministic NuGet packages (`.nupkg` + `.snupkg` symbols).
- Quickstart and ASP.NET Core example applications.

[1.0.0-alpha]: https://github.com/ilpanich/axiam-csharp-sdk/releases/tag/v1.0.0-alpha
