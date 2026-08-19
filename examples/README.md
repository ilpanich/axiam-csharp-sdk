# Axiam.Sdk (C#) — Examples

Six runnable example projects demonstrating the AXIAM C# SDK's public surface
(`Axiam.Sdk` + `Axiam.Sdk.AspNetCore`). Both build under `<Nullable>enable</Nullable>`
and reference the SDK's projects directly (not the published NuGet packages), so
they always exercise the current source tree.

## AspNetCoreSample/

A runnable ASP.NET Core 8+ web app demonstrating `Axiam.Sdk.AspNetCore`'s
middleware + `ClaimsPrincipal` injection (D-06, CONTRACT.md §10), the legacy
policy-based authorization surface (D-08), and the declarative
`[AxiamAccess(...)]` attribute (CONTRACT.md §11) — the SC#3 success-criterion
proof point.

**Build:**

```bash
dotnet build examples/AspNetCoreSample -c Release
```

**Run against a live AXIAM server (manual-only — see 21-VALIDATION.md):**

```bash
export Axiam__BaseUrl=https://your-axiam-instance
export Axiam__TenantId=your-tenant-slug
dotnet run --project examples/AspNetCoreSample
```

What to observe:

| Request | Expected result |
|---|---|
| `GET /api/me` (no `Authorization` header, no `axiam_access` cookie) | `401` — no credential presented, the framework's own `[Authorize]` rejects it |
| `GET /api/me` with `Authorization: Bearer <invalid-or-expired-token>` | `401` — `AxiamAuthMiddleware` fails closed on signature/tenant/expiry mismatch |
| `GET /api/me` with `Authorization: Bearer <valid-token>` | `200` with the injected `ClaimsPrincipal`'s `user_id`/`tenant_id`/`roles` echoed back |
| `GET /api/documents/{id}` with a valid token whose caller is DENIED `documents:read` | `403` (`AuthzError`) — routed through a fresh `CheckAccessAsync` call, D-08 |
| `GET /api/documents/{id}` with a valid token whose caller is ALLOWED `documents:read` | `200` |
| `GET /api/reports/{id}` — declarative `[AxiamAccess("read", "documents")]` (CONTRACT.md §11) — same allow/deny/401 outcomes as `/api/documents/{id}` above | `200` / `403` / `401` |
| `GET /api/reports/{id}` with a non-UUID `id` route value | `400` (`invalid_request`) — never a silent allow, never a `Guid.Empty` fallback |
| `GET /api/reports/{id}` while the AXIAM authz endpoint is unreachable | `503` (`authz_unavailable`) — fail-closed, never allow on transport failure |

## Quickstart/

A console app demonstrating all four SDK capabilities via ONLY the public
`Axiam.Sdk` entry points — no internal or generated-code references:

1. Two-phase login (`LoginAsync` → `VerifyMfaAsync` when an MFA challenge is returned)
2. REST authorization (`client.Authz.CanAsync`)
3. gRPC authorization (`AxiamGrpcAuthzClient.CheckAccessAsync`)
4. AMQP event consumption (`AxiamAmqpConsumer.StartAsync`, verify-before-handler)

**Build:**

```bash
dotnet build examples/Quickstart -c Release
```

**Run against a live AXIAM server + broker (manual-only):**

```bash
export AXIAM_BASE_URL=https://your-axiam-instance
export AXIAM_TENANT_ID=your-tenant-slug
export AXIAM_ORG_SLUG=your-org-slug        # org context for login/refresh (CONTRACT.md §5.1)
export AXIAM_EMAIL=you@example.com
export AXIAM_PASSWORD='your-password'
export AXIAM_TOTP_CODE=123456          # only needed if MFA is enabled
export AXIAM_AMQP_URI=amqps://guest:guest@localhost:5671   # §8b: amqps:// only
export AXIAM_AMQP_SIGNING_KEY_HEX=<hex-encoded per-tenant AMQP signing secret>
dotnet run --project examples/Quickstart
```

Each phase is wrapped in a try/catch so the example still builds and documents
the API shape even when run without a reachable server — the login/authz phases
print a "skipped" message rather than crashing when no server is reachable, and
the AMQP phase does the same when no broker is reachable.

## SrpLogin/

A console app demonstrating the SRP-6a login path (CONTRACT.md §23) via the public
`Axiam.Sdk` surface:

1. `LoginSrpAsync` — the password never crosses the wire, and the result is the SAME
   `LoginResult` as `LoginAsync`, MFA branch included
2. The fallback: a tenant with `srp_mode: disabled` answers `404`, which surfaces as
   `NetworkError` and **not** as a credential failure
3. `srp_required` — a `403` from `/auth/login`, which is an `AuthzError`, because the
   credentials were never examined
4. `SrpEnrollment` — the verifier the server cannot compute for itself

**Build:**

```bash
dotnet build examples/SrpLogin -c Release
```

**Run against a live AXIAM server with SRP enabled (manual-only):**

```bash
export AXIAM_BASE_URL=https://your-axiam-instance
export AXIAM_TENANT_ID=your-tenant-slug
export AXIAM_ORG_SLUG=your-org-slug
export AXIAM_USERNAME=alice                # the USERNAME, not an email — see the README
export AXIAM_PASSWORD='your-password'
export AXIAM_TOTP_CODE=123456              # only needed if MFA is enabled
export AXIAM_NEW_PASSWORD='next-password'  # optional: exercises SrpEnrollment
dotnet run --project examples/SrpLogin
```

## CI

Both examples are built by `.github/workflows/sdk-ci-csharp.yml` on every
pull request, ensuring they stay compilable against the current
SDK source tree. Neither example is executed in CI — running them end-to-end
requires a live AXIAM server (and, for the Quickstart AMQP phase, a live
RabbitMQ broker), which is manual-only per `21-VALIDATION.md`.

## TelemetryHook/

A console app demonstrating the D5 surface — CONTRACT.md §16 (bounded read-only
retry), §17 (decision memo), §18 (`Dispose`) and §19 (telemetry hooks) — with a
sink that aggregates in-process, so it runs with no metrics dependency.

**Build:**

```bash
dotnet build examples/TelemetryHook -c Release
```

**Run** (works without a reachable server — that is the point):

```bash
export AXIAM_BASE_URL=https://your-axiam-instance
export AXIAM_TENANT_ID=your-tenant-slug
dotnet run --project examples/TelemetryHook
```

Pointed at nothing, it prints:

```
WARN: MaxRetryAttempts=25 was clamped to 3 (§16.1)
WARN: DecisionMemoTtl=00:01:00 was clamped to 00:00:05 (§17.1 rule 2)
check failed: checkAccess failed: HttpRequestException — Connection refused
--- telemetry ---
  CheckAccess/Failure: count=3 mean=35ms
  retries CheckAccess: 2
  refreshes: 0
```

Both settings are deliberately configured out of range so the §19.2 rule 6
`ConfigClampedEvent` is something you *see* rather than something the comments
promise. This SDK is where that matters most: `MaxRetryAttempts` was publicly
settable **upward** before D5, which is exactly what §16.1 forbids — a caller
who can raise the cap turns one client into the herd a backoff exists to
prevent. The clamp closed it; the event is what stops the clamp being silent.

The three failed attempts with two retries between them are the §16 budget, and
counting them is only possible because §19.2 rule 5 emits one request pair per
**attempt** rather than per logical call.

The trailing comment in `Program.cs` maps each event onto its
OpenTelemetry / prometheus-net equivalent.

## UmaResourceServer/ and UmaClient/

The two halves of UMA 2.0 (CONTRACT.md §20): a resource server that answers a
denial with `WWW-Authenticate: UMA` carrying a fresh permission ticket, and a
client that consumes that header.

**Build:**

```bash
dotnet build examples/UmaResourceServer -c Release
dotnet build examples/UmaClient -c Release
```

**Run (the server first — it prints the resource id the client needs):**

```bash
export Axiam__BaseUrl=https://your-axiam-instance
export Axiam__OidcClientId=invoices-resource-server
export Axiam__OidcClientSecret=…
dotnet run --project examples/UmaResourceServer

AXIAM_INVOICE_ID=<the id it printed> dotnet run --project examples/UmaClient
```

The server shows the three setup steps in order: mint a PAT (a
client-credentials token carrying `uma_protection` — §20.2 rule 1 requires a
*client* token, since a ticket binds to the `client_id` that minted it), register
the resource (the returned id **is** the AXIAM resource id), and register a
`UmaChallenger` so a denied `[Authorize(Policy=…)]` carries a ticket.

The client shows the four request steps — refusal, parse, **trust decision**,
exchange — and makes the third one explicitly: it compares the nominated `as_uri`
against the issuer it already trusts and refuses to redeem when they differ.
`UmaChallenge.Parse` deliberately does not exchange, because the `as_uri` was
chosen by the server that just refused you.

Neither example echoes the ticket, the challenge, or any client-derived value: a
ticket is a live credential for its 60 seconds, and printing remote-chosen
strings into a terminal or log is its own hazard.

## Reactor/

A runnable §22 **reactor** — an AMQP extension actor. It subscribes to the hook events its
registration named, enriches `token.pre_issue` with `ext.` claims, and screens `login.post_auth`
(deny an embargoed region, demand step-up MFA for an admin sign-in). `ReactorServeAsync` verifies
every event under §8 v2 before the handler sees it and signs the reply with the same tenant subkey.

**Build:**

```bash
dotnet build examples/Reactor -c Release
```

**Run against a live broker (manual-only):**

The queue this consumes is declared by the **server**, from a `POST /api/v1/reactors`
registration — the reactor never declares or binds anything (§22.1), so register it first.

```bash
export AXIAM_AMQP_URI=amqps://broker.internal:5671   # §8b: amqps only, no plaintext fallback
export AXIAM_TENANT_ID=<tenant-uuid>
export AXIAM_REACTOR_ID=<reactor-uuid>               # this reactor's own registration id
export AXIAM_AMQP_SUBKEY_HEX=<derived-subkey-hex>    # a credential (§22.12) — never commit it
dotnet run --project examples/Reactor
```

What to observe: the handler is only ever reached by an event whose MAC verified, whose
`issued_at` was fresh in both directions, and whose nonce had not been seen. Kill the process
with Ctrl+C to watch the §18 drain.
