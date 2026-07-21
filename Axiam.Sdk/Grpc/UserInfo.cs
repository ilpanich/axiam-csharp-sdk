namespace Axiam.Sdk.Grpc;

/// <summary>
/// The authenticated caller's OIDC-style identity claims, returned by
/// <see cref="AxiamGrpcAuthzClient.GetUserInfoAsync"/> (CONTRACT.md &#167;1.1). The typed
/// SDK-facing projection of the wire <c>axiam.v1.GetUserInfoResponse</c> — the low-latency
/// gRPC counterpart of the server's REST <c>GET /oauth2/userinfo</c> endpoint.
/// </summary>
/// <param name="Sub">Subject (user) UUID — always present.</param>
/// <param name="TenantId">Tenant UUID — always present.</param>
/// <param name="OrgId">Organization UUID — always present.</param>
/// <param name="Email">
/// User email — populated only when the access token carries the <c>email</c> scope
/// (the server gates this exactly as the REST endpoint does); otherwise <c>null</c>.
/// </param>
/// <param name="PreferredUsername">
/// Preferred username — populated only when the access token carries the <c>profile</c>
/// scope; otherwise <c>null</c>.
/// </param>
public sealed record UserInfo(
    string Sub,
    string TenantId,
    string OrgId,
    string? Email,
    string? PreferredUsername);
