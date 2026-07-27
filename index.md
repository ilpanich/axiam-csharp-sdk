# AXIAM .NET SDK

API reference for the AXIAM .NET packages:

- **`Axiam.Sdk`** — the client: cookie-session authentication (`LoginAsync`,
  `VerifyMfaAsync`, `RefreshAsync`, `LogoutAsync`), authorization
  (`CheckAccessAsync`, `BatchCheckAsync`), the gRPC authorization client, the
  OIDC/SSO relying-party helpers (`OidcDiscoverAsync`, `OidcBegin`,
  `OidcExchangeAsync`, `OidcRefreshAsync`, `LoginClientCredentialsAsync`,
  `IntrospectAsync`, `RevokeAsync`, `SsoStartAsync`, `SsoCompleteAsync`), and the
  AMQP consumer with HMAC verification and replay protection.
- **`Axiam.Sdk.AspNetCore`** — the resource-server middleware for ASP.NET Core:
  verifies the AXIAM JWT locally against a cached JWKS, enforces the cross-tenant
  claim check, applies the CSRF double-submit check to cookie-authenticated
  state-changing requests, and wires the "Login with AXIAM" OIDC login/callback
  endpoints (`MapAxiamOidcLogin`).

See the [AXIAM SDK contract](https://github.com/ilpanich/axiam-csharp-sdk/blob/main/CONTRACT.md)
for the behaviour every AXIAM SDK guarantees.
