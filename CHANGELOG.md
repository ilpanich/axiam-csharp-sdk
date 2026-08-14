# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens**
  (contract 1.15, RFC 8705 §3 / RFC 7800). A token carrying `cnf` is **not** a bearer
  token; accepting one without proving the caller holds the named key converts it back
  into one.
  - `JwksVerifier.VerifyCertificateBinding(JsonElement claims, string? presentedThumbprint)`
    — the rule. Returns `bool` and never throws, so every failure path is a rejection.
  - `JwksVerifier.CertificateThumbprintS256(byte[] der)` — RFC 8705 §3.1 `x5t#S256`:
    base64url, **unpadded**, SHA-256 over the DER certificate. Under ASP.NET Core, feed it
    `HttpContext.Connection.ClientCertificate?.RawData`.

  **Not a breaking change, and it does not make certificates mandatory.** An *unbound*
  token is still accepted with or without a certificate.

  `VerifyAsync` deliberately does **not** apply rule 9: it has no transport to ask for a
  peer certificate. The thumbprint must come from the transport, never from a
  caller-settable header. A `cnf` naming an unimplemented method is **rejected**, never
  read as "unconstrained".

- **CONTRACT.md §21** — the FAPI 2.0 posture as an SDK sees it. Only rule 9 is normative
  for this SDK.

### Changed

- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.**


### Changed

- **Re-sync vendored `CONTRACT.md` to contract 1.14** — documentation only, no code change.
  §20.2 rule 6 (a permission ticket MUST NOT be retried) cited a "measured residual
  (ilpanich/axiam#302) … roughly 1 in 640" as its second reason. That residual is closed: the
  server now decides the ticket race with a transaction its storage engine arbitrates plus a
  redemption nonce read back after the commit. **The rule is unchanged, and this SDK's
  behaviour is unchanged** — `uma_exchange_ticket` stays excluded from every automatic retry
  path. What changed is the reasoning: the first reason (a spent ticket makes the retry
  useless) always stood alone, and the second now rests on what an SDK can actually know —
  it is talking to a server whose storage engine it cannot attest, and the guarantee is
  conditional on that engine being persistent.
- **BREAKING (contract 1.13): `TokenExchangeParams.SubjectTokenType` is now required**, losing
  its `= null` default and narrowing from `string?` to `string`.

  It shipped optional, defaulting to `AccessTokenType` — which satisfied §15.7's "never inspect
  the subject token" while leaving the rule it serves unenforced: an optional member with a
  default *is* a default the SDK applies whenever the caller says nothing. §15.1 now makes it
  required, so the positional record refuses the construction outright.

  Because a caller can still push `null` or blank through a nullable-oblivious call site, the
  SDK also refuses those **client-side with no wire call**, naming both constants. A `[Theory]`
  covers `null`, `""` and `"   "` — a blank string is the shape a config-driven caller actually
  produces.

  **Migration** — one argument, naming what you were previously getting by silence:

  ```csharp
  ExchangedToken exchanged = await client.TokenExchangeAsync(new TokenExchangeParams(
      Sensitive<string>.Wrap(userToken),
      AxiamClient.AccessTokenType,        // <- add this
      Scopes: new[] { "orders:read" }));
  ```

  This closes a gap rather than opening one: `subject_token_type` has always been required *on
  the wire*, and the SDK was covering for that with a constant which stopped being the only
  legal value when X4 landed.

### Added

- **§15.7 external-IdP subject tokens (X4).** `TokenExchangeAsync` can now exchange a token
  minted by a trusted external IdP — a partner's Entra, Okta or Keycloak — for an AXIAM token
  scoped to what the resolved AXIAM user may actually do. No new operation: the same method, plus
  `TokenExchangeParams.SubjectTokenType` and the new `AxiamClient.JwtTokenType` constant. The
  previously-private `AccessTokenType` becomes public alongside it, so a caller naming either
  value does not have to retype the URN.

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and
  a wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. A JWT-shaped subject token does **not** change what is sent, which is asserted
  by a test. (This shipped as `string? = null` with an `…:access_token` default; contract 1.13
  made it required — see *Changed* above.)

  The property sits second in the `TokenExchangeParams` record, next to the `SubjectToken` it
  describes and matching the other SDKs.

  Also asserted: an `ActorToken` alongside an external subject token surfaces `invalid_request`
  with no retry and no request rewriting; a refused refresh or ID token type is never retried as
  a different type; the one normative description — `the subject token's issuer is not configured
  for token exchange`, meaning *fix the AXIAM trust config* rather than *fix your token* —
  reaches the caller intact; and nothing re-exchanges an exchanged token, which both server paths
  refuse because exchanges do not compose.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.10 → 1.12
  plus §15.7), which also brings contract 1.11's lifted §12.6 deferral, contract 1.12's
  `/oauth2/*` error rows dispatching on the `error` field at any status, and the
  `TokenExchangeTrust` schemas behind the X4 provider configuration.

- **§20.3 challenge emission from the §11 policy handler.** `AddAxiamUmaChallenge(...)`
  registers a `UmaChallenger` (realm, `as_uri`, PAT); with one registered, a denied
  `[Authorize(Policy=…)]` mints a permission ticket for the action that was refused and
  `AxiamAuthorizationMiddlewareResultHandler` returns it as `WWW-Authenticate: UMA` alongside
  the unchanged 403 body.

  It is **opt-in** because emitting a challenge means minting a credential: a handler that did
  it by default would turn every unauthorized request into a Protection API call, which is a
  denial-of-service amplifier pointed at your own authorization server. An allow mints nothing.
  And a **minting failure is not an escalation** — an expired PAT or an unreachable Protection
  API still yields the plain 403, never a 503 and never an allow. Both are asserted by counting
  Protection API calls. The requested scope is the AXIAM *action*, so the ticket asks for
  exactly the authority just refused and the engine's deny rules keep applying to whatever RPT
  comes back.

  Paired with the new `examples/UmaResourceServer` and `examples/UmaClient` (both built in CI),
  which run the emit and consume halves — including the trust decision §20.3 keeps in the
  caller's hands rather than auto-exchanging against whatever host a 403 named.

- **§20 UMA 2.0 — Protection API and ticket grant (contract 1.10).** New methods on
  `AxiamClient`: `UmaRegisterResourceAsync` / `UmaReadResourceAsync` / `UmaUpdateResourceAsync` /
  `UmaDeleteResourceAsync` / `UmaListResourcesAsync`, `UmaRequestTicketAsync`,
  `UmaExchangeTicketAsync`, plus the `ResourceSet` / `RequestedPermission` / `RptPermission` /
  `RequestingPartyToken` records and `UmaChallenge` with its static `Parse` / `Header` helpers.

  Two behaviours are load-bearing rather than incidental, and both are asserted by counting
  requests. **`UmaExchangeTicketAsync` never retries** — the one documented exception to the
  §16 retry policy, because a ticket is consumed before the request is evaluated, so a retry
  cannot succeed and under concurrency is exactly the second redemption that
  ilpanich/axiam#302's measured residual describes. And **`UmaChallenge.Parse` does not
  exchange the ticket it parsed**: the `as_uri` names an authorization server the caller has
  not chosen to trust.

  The PAT is an explicit first argument on every Protection API call rather than being taken
  from the client's session, because that session is usually a *user* session and a ticket
  binds to a `client_id`.

  `access_denied` on the ticket grant arrives as **403** (UMA 2.0 §3.3.6), unlike RFC 8628's,
  which is a 400. It is mapped to `OAuthProtocolError` by a mapper local to this grant rather
  than by widening `MapOAuth2ErrorAsync`'s 400/401 rows — an ordinary REST 403 still maps to
  `AuthzError`.

  `UmaChallenge.Parse` returns `null` for a non-UMA scheme, and `Sensitive<string>` is a
  struct here, so its nullable ticket is read through `.Value`.

- **§19 `ConfigClampedEvent` (contract 1.9).** The SDK now reports every setting it clamped,
  once per setting, at construction — `MaxRetryAttempts`, `RetryBaseDelay`, `RetryMaxDelay`
  (§16.1) and `DecisionMemoTtl` (§17.1 rule 2). Clamping is right; clamping *silently* is not:
  an operator who set a 60-second memo TTL believes they have one, and their staleness
  reasoning is off by a factor of twelve with nothing anywhere to say so. Nothing is emitted
  for a value already within its limit, or for a value that was lowered — an event that fires
  when nothing happened trains its reader to ignore it.

### Fixed

- **The §16 retry configuration was never wired.** `MaxRetryAttempts`, `RetryBaseDelay` and
  `RetryMaxDelay` were defaulted, documented, and asserted in `CoreValueTypesTests` — and read
  by no production code; their own doc comment said "not yet wired into any call path". The SDK
  therefore performed **no read-only retries at all** while presenting three knobs that looked
  like it did, leaving §11.2 rule 5's requirement silently unmet. They are wired now, and the
  conformance tests assert the policy through the public `CheckAccessAsync` surface by counting
  requests on the wire.
- **§16.1: the caller can no longer raise the policy above the contract.** All three settings
  are now clamped *down* to the contract's values. §16.1 permits lowering the attempt cap or
  disabling retry, never raising either — a caller who could raise them turns one client into
  the thundering herd the policy exists to prevent. Lowering still works; the clamp is
  one-directional.

### Added

- **§16 bounded read-only retry policy** (`Core/RetryPolicy.cs`): 3 attempts, 200 ms base, 5 s
  cap, **full jitter** over `[0, backoff]`, `Retry-After` honored as a floor.
- **§18 `Dispose()` semantics** — idempotent via `Interlocked`, clears the memo, and
  use-after-dispose throws `ObjectDisposedException` rather than silently reconnecting. It does
  **not** log out and never reaches the network.
- **§19 telemetry hooks** — `AxiamClientOptions.TelemetryHook`, plus the closed
  `TelemetryEvent` hierarchy (`RequestStartEvent`, `RequestEndEvent`, `RetryEvent`,
  `RefreshEvent`). A throwing hook cannot fail the operation that fired it (except
  `OperationCanceledException`, which propagates), and no event payload can carry a token. One
  request pair per *attempt*.
- **§17 decision memo — opt-in, off by default** — `AxiamClientOptions.DecisionMemoTtl`, clamped
  to 5 s, thread-safe. Allows and denies memoized identically, failures never memoized, cleared
  on any credential change. **Reads-your-own-writes is not guaranteed.**
- `AxiamClientOptions.RetryEnabled` (§16.6), default `true`.
- `NetworkError.RetryAfter`, a parsed `TimeSpan` rather than the raw header text, so the
  fail-closed redaction allowlist is untouched. Both RFC 7231 forms parse.

### Changed

- Re-vendored `CONTRACT.md` at **1.8.2**. `openapi.json` unchanged — docs-only contract revs.
- `LoginAsync`, `VerifyMfaAsync`, `RefreshAsync` and `LogoutAsync` clear the decision memo
  (§17.1 rule 9) and reject after dispose (§18.1 rule 4).

## [1.0.0-alpha24] - 2026-08-04

### Added

- Add AxiamWebhooks.Verify signature verifier (CONTRACT.md §13, T-145)

### Changed

- Add the §10.1 rule-8 guardrail regression tests (#33)
- Device (mTLS) tokens now carry aud=axiam:m2m (#32)
- Service accounts can use login_client_credentials (#31)
- Sync CONTRACT.md §10.1 rule 8 — subject of the decision (#30)
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Bump the minor-patch group with 2 updates

### Fixed

- Assert tenant_id against the configured tenant, not a header
- Enforce the full CONTRACT §10.1 local-verification set

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
