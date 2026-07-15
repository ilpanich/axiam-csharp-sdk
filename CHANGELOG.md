# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
