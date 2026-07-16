# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-alpha2] - 2026-07-16

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
