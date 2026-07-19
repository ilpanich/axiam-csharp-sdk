# Axiam.Sdk (C#) — Examples

Two runnable example projects demonstrating the AXIAM C# SDK's public surface
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
export AXIAM_AMQP_URI=amqp://guest:guest@localhost:5672
export AXIAM_AMQP_SIGNING_KEY_HEX=<hex-encoded per-tenant AMQP signing secret>
dotnet run --project examples/Quickstart
```

Each phase is wrapped in a try/catch so the example still builds and documents
the API shape even when run without a reachable server — the login/authz phases
print a "skipped" message rather than crashing when no server is reachable, and
the AMQP phase does the same when no broker is reachable.

## CI

Both examples are built by `.github/workflows/sdk-ci-csharp.yml` on every
pull request, ensuring they stay compilable against the current
SDK source tree. Neither example is executed in CI — running them end-to-end
requires a live AXIAM server (and, for the Quickstart AMQP phase, a live
RabbitMQ broker), which is manual-only per `21-VALIDATION.md`.
