# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-alpha41] - 2026-08-24

### Added

- Honour login/start `mode` when KE2 does not open (§23.4 rule 7)

### Changed

- Re-vendor openapi.json for the vault_pki CA custodian (axiam#368)
- Re-vendor CONTRACT.md 1.29 and openapi.json 1.0.0-alpha40

## [1.0.0-alpha40] - 2026-08-23

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha39.

## [1.0.0-alpha39] - 2026-08-23

### Changed

- Re-vendor CONTRACT.md for the §14.1 anchor repair
- Claim §20, which this SDK has shipped since contract 1.10
- Re-vendor openapi.json at 1.0.0-alpha38

## [1.0.0-alpha38] - 2026-08-22

### Changed

- Fix nullable-struct access in the AccountLifecycle example
- Fix nullable-struct access on LoginResult.SetupToken in tests
- Re-vendor CONTRACT.md at 1.28
- Add WebAuthn, account lifecycle and PAR (CONTRACT §24–§26)

## [1.0.0-alpha37] - 2026-08-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha34.

## [1.0.0-alpha34] - 2026-08-21

### Added

- Replace SRP-6a with OPAQUE (RFC 9807), CONTRACT §23

### Changed

- Link to the AXIAM platform documentation site
- Re-vendor openapi.json at alpha32 (#59)

### Fixed

- Build the KSF before spending the exchange's state handle

## [Unreleased]

### Changed

- **Re-vendor `openapi.json`** for AXIAM server PR #368, which adds a third CA
  key custodian, `vault_pki`, having HashiCorp Vault's PKI secrets engine
  generate the CA key inside Vault and sign on AXIAM's behalf. The spec version
  is unchanged at **1.0.0-alpha40**; `CONTRACT.md` and `proto/` are untouched by
  that PR and are already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto `/api/v1/organizations/{org_id}/ca-certificates`, and this SDK
  models none of the five schemas below — so nothing here gains, loses, or
  changes a symbol. It is vendored so the spec this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - `CaCertificate` gains a nullable `chain_pem`: the issuers above
    `public_cert_pem`, concatenated PEM, nearest issuer first and the root last.
    Absent for a CA that is its own root, which is every CA AXIAM generated
    before this. Present for a `vault_pki` CA, where it is the only copy of the
    root certificate anything outside Vault will ever see.
  - `CaCertificate.public_cert_pem` is now documented as the certificate that
    *signs*, which under `vault_pki` custody is the intermediate rather than the
    root beneath which it was created. The field itself is unchanged.
  - `GeneratedCaCertificate.private_key_pem` is **no longer required**. Under
    `vault_pki` custody the key is born inside Vault and no API exports it, so
    there is nothing to return. The field is omitted rather than sent as `null`,
    which keeps a client that has always read it working unchanged against every
    custodian that does produce a key.
  - `GeneratedCertificate` gains a nullable `chain_pem`, present only when the
    signer returned one — the `vault_pki` case, where the root's certificate
    exists nowhere a client could fetch it from.
  - `CreateCaCertificate` and `CreateCaCertificateRequest` gain the optional
    `issue_from_root`, `intermediate_subject` and `intermediate_validity_days`.
    All three are `vault_pki`-only and ignored by every other custodian.
    `issue_from_root` defaults to off: a root that signs only one intermediate
    can have that intermediate revoked and replaced without redistributing the
    trust anchor, and a root that signs leaves directly cannot.

- **BEHAVIOUR** — CONTRACT.md §23.4 rule 7, contract 1.29. The
  `POST /api/v1/auth/opaque/login/start` response now carries an optional `mode`
  field holding the tenant's `opaque_mode`, and it alone decides what a failed
  `KE2` means. `LoginOpaqueAsync` still sends nothing to `login/finish` when the
  envelope does not open, but under `mode: "optional"` it now **retries over
  `POST /api/v1/auth/login`** with the same credentials and returns that call's
  outcome — its success on success, its error on failure — instead of raising
  immediately. Under `mode: "required"`, under an **absent** `mode` (a server
  older than the field) and under any value this SDK does not recognise, the
  failure stays an `AuthError`, the exchange is over, and nothing is retried.

  This is not belt-and-braces: `optional` is the mid-migration state, every
  account starts with no registration record and acquires one only when its
  password is next set, so treating the failed exchange as final locked out
  every user of a tenant that had just enabled OPAQUE. A caller that already
  wrapped `LoginOpaqueAsync` in its own fallback should remove it — under
  `required` a retry is refused with `403 opaque_required` anyway, and it puts a
  plaintext password on the wire for nothing.

  `mode` is **not** downgrade protection and is not documented as such: a
  hostile server that wanted the plaintext could answer `404` and get a fallback
  whatever it puts there. Only a `NetworkError` path (a `404`, an absent
  library, an unusable key-stretching function) is unchanged — those are not
  credential checks and never trigger the fallback.
- Re-vendored `CONTRACT.md` at contract **1.29** and `openapi.json` at
  **1.0.0-alpha40**.

### Added

- CONTRACT.md §24 — WebAuthn / passkeys relying-party layer (`Axiam.Sdk.Webauthn`):
  the six wire operations, the two distinct authentication ceremonies, and
  §24.6a's JSON bridge. `WebauthnChallenge.RequestJson` is the string an
  ASP.NET Core relying party hands to a browser (or a MAUI/Uno host), and the
  platform's response JSON goes straight back into the matching `*FinishAsync`
  — spliced into the request body as text so the authenticator's signed bytes
  reach the wire unmodified. `WebauthnFailures.Classify` maps a relayed
  platform error name to the five §24.6b rule 5 outcomes.

  §24.6b's linked-API helper is deliberately absent: a server or CLI runtime
  has no authenticator, and rule 2 forbids emulating one in software.
- CONTRACT.md §25 — account lifecycle and MFA enrolment (`Axiam.Sdk.Account`):
  voluntary and forced TOTP enrolment, email verification, and the
  password-reset triple including the `reset/context` call a tenant with §23
  enabled requires before a new password can be built.
- CONTRACT.md §26 — Pushed Authorization Requests, RFC 9126 (`OidcParAsync`,
  `OidcParParams`, `PushedAuthorizationRequest`). Required for a FAPI 2.0
  client, which cannot authorize any other way (§21.1).
- `examples/WebauthnPasskeys`, `examples/AccountLifecycle` and
  `examples/ParLogin`, each built by CI.

### Changed

- Re-vendor `CONTRACT.md`. Repairs §14.1's link to the `device_login` heading,
  which dropped a hyphen the em dash leaves behind and so rendered as a link
  that went nowhere; the same heading's other two links were already correct.
  Link target only — no normative change and no contract-version bump.

- **Conformance statement now names §20.** The UMA 2.0 Protection API and ticket
  grant — all seven §20.1 canonical operations — have been on `AxiamClient` since
  contract 1.10 and are documented in the README body; the headline statement had
  never been widened to say so.

- Re-vendor `openapi.json` at **1.0.0-alpha38**. The server registered the four
  GDPR data-subject endpoints (`POST /api/v1/account/export`,
  `GET /api/v1/account/export/{token}`, `POST /api/v1/account/delete`,
  `GET /api/v1/auth/account/delete/cancel`), taking the document to 181
  operations across 121 paths. Purely additive, and no SDK surface changes with
  it: nothing in this repo is generated from the spec, so the cross-repo
  artifact-drift gate was the only thing reporting `STALE`.

- `LoginResult` gained `MfaSetupRequired` and `SetupToken` for §25.2 rule 1's
  third login outcome. Both default, so every existing construction still
  compiles and reads `false`. Callers that branch only on `MfaRequired` should
  still add the new branch — a tenant that turns on required MFA will start
  returning it, and ignoring it reports a successful login that has no session.
- `OidcConfiguration` gained `PushedAuthorizationRequestEndpoint`, defaulted to
  `null` and parsed from discovery.
- Re-vendored `CONTRACT.md` and `openapi.json` at contract 1.28.

### Added

- OPAQUE (RFC 9807) login and enrolment (CONTRACT §23): `LoginOpaqueAsync`,
  `OpaqueEnrollmentAsync` and `OpaqueAvailable` on `AxiamClient`, plus the new
  `Axiam.Sdk.Opaque` namespace.
- `examples/OpaqueLogin`.

### Changed

- Re-vendor `openapi.json` at **1.0.0-alpha32**, matching the server. The
  content was already byte-identical in every path and schema; only
  `info.version` differed, which is what the cross-repo artifact-drift gate
  reports as `STALE`.
- **BREAKING** — the OPAQUE protocol is NOT implemented in this SDK. CONTRACT
  §23.1 forbids it, so the client half is a P/Invoke binding to
  `libaxiam_opaque_ffi` — the same implementation the AXIAM server links,
  published as a per-platform asset on the axiam release page rather than on
  NuGet. There is nothing to add to your `.csproj`; put the library where the
  runtime probes for native libraries, or set `AXIAM_OPAQUE_LIBRARY`.
- **BREAKING** — `OpaqueAvailable()` can genuinely return `false`, where
  `SrpAvailable()` was hard-coded `true` on .NET. Code that ignored
  `SrpAvailable()` must not ignore this one. It calls into the library rather
  than merely locating it: a .NET P/Invoke does not resolve until first use, so a
  probe that only found the file would report "present" and then throw at login.
- **BREAKING** — enrolment is now asynchronous and performs network I/O, where
  `SrpEnrollment` was a pure computation: OPAQUE's envelope is sealed under the
  server's oblivious PRF, so there is no offline computation that produces a
  valid record. It also drops the `identity`, `group` and KDF parameters — a
  record binds to a credential identifier the server chooses, and the
  key-stretching parameters are the server's. As a consequence, **renaming a
  user no longer invalidates their credential**.
- Failure taxonomy for the OPAQUE path: a tenant with OPAQUE disabled, an absent
  library, and a key-stretching function this build cannot perform are all
  `NetworkError` (a caller can fall back, or an operator can act); everything
  else is `AuthError` and must NOT be retried over `LoginAsync` (§23.4 rule 7).
  Amended by contract 1.29 — see the `mode` entry at the top of this section.

### Removed

- **BREAKING** — SRP-6a. `LoginSrpAsync`, `SrpEnrollment`, `SrpAvailable`, the
  whole `Axiam.Sdk.Srp` namespace, `srp-test-vectors.json` and
  `examples/SrpLogin` are all gone. AXIAM's server-side SRP endpoints are removed
  in the same release, so keeping the client would leave methods that only ever
  return 404.

### Fixed

- OPAQUE: a refused key-stretching function no longer strands the exchange's
  native state handle. `Finish()` spent the handle before building the KSF, so
  an unrecognised function or an out-of-band cost left it out of its one-shot
  slot and unreachable by `Dispose()` or the finalizer — a leaked Rust
  allocation once per login attempt against a misconfigured tenant. The KSF is
  now built first, so a refusal leaves the exchange intact: it is released
  normally, and a caller who fixes the parameters can retry.

## [1.0.0-alpha31] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha30.

## [1.0.0-alpha30] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha29.

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP-6a login client (CONTRACT §23) (#56)

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Re-vendor openapi.json at 1.0.0-alpha27 (#55)
- Bump xunit.runner.visualstudio from 3.1.5 to 4.0.0
- Bump the minor-patch group with 5 updates

## [1.0.0-alpha27] - 2026-08-17

### Added

- ReactorConnections — enforce §8b instead of documenting it
- §22.14 declarative reactor handler binding — ReactorHandlers
- **`ReactorConnections` — CONTRACT.md §8b enforced rather than described.**
  `ReactorServeOptions.Channel` takes an already-open channel, and §8b's
  requirements travelled with it as a doc-comment sentence: "its connection MUST
  have been opened over `amqps://` with a trusted CA". A doc-comment MUST is a
  note to whoever reads the doc comment — a caller who built a
  `ConnectionFactory` from an `amqp://` URI got a working reactor, no warning,
  and signed-but-readable token decisions on the wire.

  `ReactorConnections.CreateConnectionFactory(...)` refuses every scheme but
  `amqps://` (rules 1 and 5, with no loopback exception and no pass-through for
  an unparseable URI), accepts the broker's CA for a privately issued
  certificate (rule 2), accepts a client certificate for mutual TLS and refuses
  one that carries no private key (rule 3), pins `AcceptablePolicyErrors` to
  `None`, and sets `Ssl.ServerName` from the URI — a blank `ServerName` is how
  hostname verification quietly becomes nothing.

  It is deliberately the counterpart of the Kotlin and Java helpers: SDKs should
  not disagree about what a reactor may connect to. `ReactorServeOptions` still
  accepts any channel, since enforcing at construction cannot retroactively
  constrain one somebody else opened.

### Changed

- Re-vendor CONTRACT.md 1.23 (§8b rules 7 and 8)
- Re-vendor openapi.json for the SCIM provisioning-token endpoints
- Re-vendor CONTRACT.md 1.22 from the server repo
- Re-vendor `openapi.json` at 1.0.0-alpha27 — the copy was pinned at alpha26 and
  failing the cross-repo artifact-drift gate
- **BREAKING: `AxiamAmqpConsumer.StartAsync` refuses a non-`amqps://` URI.** It
  previously accepted any scheme `ConnectionFactory` would take, including
  plaintext `amqp://` — the same §8b gap, on the §8 consumer path. A signed
  `AuthzRequest` still names its subject, resource and action in cleartext; HMAC
  proves who wrote the message, it does not keep the message off the wire.

  The quickstart example's default URI moves from
  `amqp://guest:guest@localhost:5672` to `amqps://guest:guest@localhost:5671`.

## [1.0.0-alpha25] - 2026-08-16

### Added

- Adopt CONTRACT §11.2 rule 9 reason accessor (SDK-Q10)
- Ship the §22 reactor runtime (R2.5) (#49)
- Extend §10.1 rule 9 for DPoP and implement §21.7.2 (#46)
- SubjectTokenType is required (contract 1.13)
- §15.7 — external-IdP subject tokens at the exchange (X4)
- §20.3 — emit a UMA challenge from the §11 policy handler (#40)
- §20 — UMA 2.0 Protection API and ticket grant
- Report clamped settings via §19 ConfigClampedEvent (contract 1.9)
- Wire §16 retry (it never was), §17 memo, §18 dispose, §19 telemetry (D5)
- Device grant, token exchange, logout helpers; re-vendor (D6)
- **CONTRACT.md §22 — the reactor runtime (`Axiam.Sdk.Reactor`).** A reactor is an
  external process subscribed to named hook events on the AMQP bus, answering
  allow / deny / mutate inside a timeout the server declared.
  `ReactorServer.ReactorServeAsync(options)` consumes the **server-declared** queue,
  verifies each event under §8 v2 (key version, MAC, freshness, nonce, in that
  order) before the handler sees it, and signs the reply with the same tenant
  subkey.

  The canonicalization difference that costs a day if it is not stated: a reactor
  body is signed with `hmac_signature` **present and set to `null`**, where
  `Amqp/Hmac.cs` *removes* the field for §8's own two message types.
  `Reactor/ReactorProtocol.cs` is the only place that rule lives, and
  `ReactorVectorTests` proves it byte-for-byte against the server-generated §22.13
  vectors — canonical bytes, MAC, the omission of `reason`/`patch` when absent and
  of `require_mfa` when false, the `nonce_binding` pair, the `correlation_replay`
  refusal, the stale/future pair, and the topology strings. Both fixtures ship
  side by side under the same master key, tenant and derived subkey, so one loader
  serves both and the §8-vs-§22 difference is a test rather than a paragraph to
  remember.

  §8's replay gate is **reused, not reimplemented**: the runtime runs the same
  `Amqp.ReplayGuard` the audit/authz consumer runs, because two implementations of
  one security control is one too many. No public surface widened to do it — the
  guard's clock seam was already `internal`.

  Four rules are structural rather than documented. The runtime declares no
  exchange, queue or binding (asserted against `Mock<IChannel>.Invocations`, so it
  is a claim about behaviour rather than about source); a handler that throws
  produces **no reply** rather than a synthesized `allow`, so the operator's
  `failure_policy` still decides; a patch is sent **unfiltered**, because dropping a
  forbidden key would leave the author believing it was set; and a reply is
  abandoned rather than published after `timeout_ms` has elapsed.
  `ReactorDecision` is a closed hierarchy in which `Allow` cannot carry a patch and
  `Mutate` cannot be empty, and the listener delegate returns a plain `Task`, so a
  listener cannot publish a reply at all.

  §22.7 is honoured as the MUST NOT it is: `authz.check`, `authz.check_batch` and
  `token.introspect` are absent from `ReactorEvents.Registry` and from every
  constant this SDK exposes, asserted against the reflected list rather than a
  comment, and no interceptor equivalent is offered for them anywhere.

  Interacts with the existing surfaces as they already work: `DisposeAsync` is
  §18-deterministic (cancel, drain, idempotent, and it leaves the caller's channel
  and connection open), §19 emits one `RequestStartEvent`/`RequestEndEvent` pair per
  dispatch with the event name as the path template, the signing key is wrapped in
  `Sensitive<byte[]>` per §22.12 and asserted absent from every log line, and §16
  retry deliberately does **not** apply to a reply — a correlation is single-use, so
  a resend could only add load to a server that has already moved on.

  Adds `examples/Reactor` (a token enricher plus a login screen, compile-gated in
  CI) and a README chapter. No new package dependency: `RabbitMQ.Client` was
  already referenced for §8.

- **CONTRACT.md §10.1 rule 9 extended for DPoP, and §21.7.2 proof verification
  implemented (contract 1.16/1.17).**

  `JwksVerifier.VerifyTokenBinding()` applies the full ten-row rule against a
  certificate thumbprint, a verified DPoP key thumbprint, or **both**. A `cnf`
  naming both methods is a **conjunction** — satisfying only the more convenient
  one is not compliance — and a `cnf` naming nothing this SDK can check (including
  an *empty* one, which is how proto3 delivers an empty `CnfClaim`) is refused
  rather than read as unbound. `VerifyCertificateBinding()` remains for
  certificate-only transports and now **refuses** a DPoP-bound or both-bound token
  rather than ignoring the half it cannot check.

  New `DpopVerifier` implements all ten §21.7.2 checks and returns the proof key's
  RFC 7638 thumbprint, so a value passed to `PresentedProofs` could only have come
  from a proof that verified. `DpopVerifier.InMemoryJtiStore` covers check 8 for a
  single process; the `IJtiStore` argument is required, not optional, because there
  is no safe default that skips replay tracking.

  Ed25519 goes through BouncyCastle for the same reason `JwksVerifier` does — .NET
  still ships no EdDSA — while `ES256` and `PS256` use the platform's own `ECDsa`
  and `RSA`. Two encoding details that silently break interop if missed: JWS ES256
  signatures are raw `r||s` (IEEE P1363), **not** the DER form `VerifyData` assumes
  by default, and PS256 is RSASSA-**PSS**, not PKCS#1 v1.5.

  Not a breaking change: an unbound token is still accepted with no certificate and
  no proof, asserted directly by the first test in the new group.

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

- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#48)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#45)
- Add the §20.7 required timeout assertion
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
- Bump the minor-patch group with 1 update
- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.**
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
- Re-vendored `CONTRACT.md` at **1.8.2**. `openapi.json` unchanged — docs-only contract revs.
- `LoginAsync`, `VerifyMfaAsync`, `RefreshAsync` and `LogoutAsync` clear the decision memo
  (§17.1 rule 9) and reject after dispose (§18.1 rule 4).

### Fixed

- R5.7 remediation — F-13, F-15 (F-16 verified) (#47)
- Route the bool surface through D5 + runnable §16–§19 example (F3) (#38)
- **SDK-Q10 (contract 1.19): the gRPC `AccessDecision` mapper never read `reason` and
  always surfaced the deprecated `deny_reason`.** `proto/axiam/v1/authorization.proto`
  already carried the CONTRACT.md §11.2 rule 9 amendment — `reason` (field 4, explicit
  presence, absent on an allow and present on every refusal) as the canonical name, with
  `deny_reason` (field 2) marked `[deprecated = true]` and removed at AXIAM 2.0 — but
  because this SDK generates its gRPC stubs into a gitignored `obj/` directory at build
  time, nothing forced the client mapper to catch up: `AxiamGrpcAuthzClient.ToDecision`
  kept reading only `DenyReason`, unnoticed by any build. `ToDecision` now reads
  `Reason` when `CheckAccessResponse.HasReason` is true, and falls back to the
  deprecated `DenyReason` **only** when `Reason` is absent **and** the decision is a
  refusal (`!Allowed`) — guarding on `HasReason` rather than truthiness so an
  explicitly-empty `Reason` on a refusal is never misread as absent. `AccessDecision`
  already exposed exactly one reason accessor (`Reason`); no public signature changes.
  **Deliberately not taken:** relaxing gRPC `subject_id` to optional — contract 1.19
  makes an empty wire value mean "the token's subject", but changing the SDK-facing
  parameter's nullability is a breaking signature move every sibling SDK has likewise
  deferred.
- **F-15: `X-Tenant-Id` was silently dropped on `/oauth2/*` requests whose absolute URL
  (taken from the discovery document) targets a host other than the client's configured
  base URL.** `AxiamHttpMessageHandler`'s host-isolation guard (3A) previously withheld
  every header — tenant, bearer, and CSRF alike — from any foreign-host request.
  CONTRACT.md §12.1 note 2 calls `X-Tenant-Id` unconditional on `/oauth2/*` regardless of
  host, so a gateway/CDN-fronted deployment that advertises `token_endpoint` on a
  different host than `BaseUrl` would silently lose the header. `Authorization`/
  `X-CSRF-Token` still stay same-origin only (3A) — neither is meaningful to `/oauth2/*`,
  which authenticates via `client_secret_post`, never bearer. Harmless in practice (the
  server's `/oauth2/*` handlers read tenant context only from the `?tenant_id=` query
  parameter, never the header), but no test asserted the header on a `/oauth2/token`
  request until now.
- **F-13: the §12.4 rule 7 (all-or-nothing discard) test only asserted that an exchange
  throws, not that the same response's sentinel access/refresh token is absent from the
  outcome or the exception.** Strengthened to match the five sibling SDKs.
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

## [1.0.0-alpha24] - 2026-08-04

### Added

- Add AxiamWebhooks.Verify signature verifier (CONTRACT.md §13, T-145)
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

- Add the §10.1 rule-8 guardrail regression tests (#33)
- Device (mTLS) tokens now carry aud=axiam:m2m (#32)
- Service accounts can use login_client_credentials (#31)
- Sync CONTRACT.md §10.1 rule 8 — subject of the decision (#30)
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Bump the minor-patch group with 2 updates
- Re-sync the vendored `CONTRACT.md` with the new normative §10.1.

### Fixed

- Assert tenant_id against the configured tenant, not a header
- Enforce the full CONTRACT §10.1 local-verification set

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

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

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
