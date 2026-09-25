using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.V1;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Grpc.Net.Client;

namespace Axiam.Sdk.Grpc;

/// <summary>
/// The &#167;10.3 sender-constraint, modelled once (RFC 8705 &#167;3 / RFC 9449 &#167;6). Both
/// members are the raw proto3 string default (<c>""</c>) rather than <c>null</c> when
/// unset on the wire — CONTRACT.md &#167;1.1.1 rule 3 requires the distinction between
/// "no <c>cnf</c> at all" (<see cref="TokenValidation.Cnf"/>/<see cref="TokenIntrospection.Cnf"/>
/// itself <c>null</c>) and "a <c>cnf</c> naming neither method" (this record present with
/// both members empty) to survive into the typed value.
/// </summary>
public sealed record TokenCnf(string X5tS256, string Jkt);

/// <summary>
/// A UMA 2.0 permission carried by an RPT (X2), from <see cref="TokenIntrospection.Permissions"/>.
/// </summary>
public sealed record RptPermission(string ResourceId, IReadOnlyList<string> ResourceScopes, long Exp);

/// <summary>
/// CONTRACT.md &#167;10.3 rule 2's four-way answer to "is this token usable as
/// presented?" — deliberately NOT reducible to <c>valid</c>/<c>active</c> alone (that is
/// the whole point of &#167;10.3): a caller that only checks the boolean has converted a
/// sender-constrained token back into a bearer token.
/// </summary>
public enum TokenStatus
{
    /// <summary><c>valid</c>/<c>active</c> was <c>false</c> — the signature, expiry or
    /// tenant check failed, or this token belongs to a different tenant (&#167;10.3 rule
    /// 6). Not an error; the server answered "not a token of yours" or "not usable".</summary>
    Inactive,

    /// <summary>Usable, and carries no <c>cnf</c> at all — an ordinary bearer token.</summary>
    Bearer,

    /// <summary>Usable, and <c>cnf</c> names at least one confirmation method this client
    /// can check against <see cref="PresentedProofs"/>. Call <c>VerifyPossession</c>
    /// before treating it as usable BY THE CALLER, not just usable in the abstract.</summary>
    SenderConstrained,

    /// <summary><c>cnf</c> is present but names neither method (including an EMPTY
    /// <c>CnfClaim</c> — &#167;10.3 rule 3: proto3 cannot express "absent string", so this
    /// is the wire spelling of &#167;10.1 rule 9's "names neither" row). MUST NOT be read
    /// as unbound.</summary>
    Unverifiable,
}

/// <summary>
/// <c>axiam.v1.TokenService/ValidateToken</c>'s typed response (CONTRACT.md &#167;1.1.1
/// rule 3): every field the message defines, <see cref="Cnf"/> included.
/// </summary>
public sealed record TokenValidation(
    bool Valid, string SubjectId, string TenantId, string OrgId, long Exp, TokenCnf? Cnf, string TokenType)
{
    /// <summary>&#167;10.3 rule 2 in one call — see <see cref="TokenStatus"/>.</summary>
    public TokenStatus Status() => TokenStatusHelper.Compute(Valid, Cnf);

    /// <summary>
    /// &#167;10.1 rule 9 with evidence from the CALLER'S OWN connection (never the
    /// connection this gRPC call itself travelled on — this service cannot prove
    /// possession for you, only tell you what the token requires). <c>true</c> when the
    /// token is unbound, or bound and the matching proof(s) are present; <c>false</c>
    /// otherwise, including for <see cref="TokenStatus.Unverifiable"/>.
    /// </summary>
    public bool VerifyPossession(PresentedProofs proofs) =>
        SenderConstraintRule.Verify(Cnf is not null, Cnf?.X5tS256, Cnf?.Jkt, proofs);
}

/// <summary>
/// <c>axiam.v1.TokenService/IntrospectToken</c>'s typed response (CONTRACT.md &#167;1.1.1
/// rule 3): the RFC 7662 field set, <see cref="Cnf"/> and <see cref="Permissions"/>/
/// <see cref="ExtExchangeIss"/> included.
/// </summary>
public sealed record TokenIntrospection(
    bool Active, string Sub, string TenantId, string OrgId, string Iss, long Iat, long Exp, string Jti,
    string Scope, string ClientId, string TokenType, TokenCnf? Cnf,
    IReadOnlyList<RptPermission> Permissions, string ExtExchangeIss)
{
    /// <summary>&#167;10.3 rule 2 in one call — see <see cref="TokenStatus"/>.</summary>
    public TokenStatus Status() => TokenStatusHelper.Compute(Active, Cnf);

    /// <summary>Same rule as <see cref="TokenValidation.VerifyPossession"/>.</summary>
    public bool VerifyPossession(PresentedProofs proofs) =>
        SenderConstraintRule.Verify(Cnf is not null, Cnf?.X5tS256, Cnf?.Jkt, proofs);
}

/// <summary>Shared by both response types' <c>Status()</c>.</summary>
internal static class TokenStatusHelper
{
    internal static TokenStatus Compute(bool usable, TokenCnf? cnf)
    {
        if (!usable)
        {
            return TokenStatus.Inactive;
        }
        if (cnf is null)
        {
            return TokenStatus.Bearer;
        }
        bool namesAny = !string.IsNullOrEmpty(cnf.X5tS256) || !string.IsNullOrEmpty(cnf.Jkt);
        return namesAny ? TokenStatus.SenderConstrained : TokenStatus.Unverifiable;
    }
}

/// <summary>
/// <c>validate_token</c>/<c>introspect_token</c> (CONTRACT.md &#167;1.1.1, &#167;10.3,
/// contract 1.51) — <c>axiam.v1.TokenService</c>. Built exactly like
/// <see cref="AxiamGrpcAuthzClient"/>: the shared long-lived channel, the same
/// <see cref="AuthInterceptor"/> the REST-sharing session uses, and
/// UNAUTHENTICATED-&gt;single-flight-refresh-&gt;one-retry via the SAME
/// <see cref="RefreshGuard"/> — never a second guard instance.
/// </summary>
/// <remarks>
/// CONTRACT.md &#167;1.1.1 rule 1: two credentials travel on one call, and this class keeps
/// them apart structurally. The CALLER's token authenticates the RPC itself, through the
/// interceptor exactly as every other gRPC call on this channel is authenticated — this
/// class never reads it directly. The INSPECTED token is a required
/// <see cref="Sensitive{T}"/> parameter of <see cref="ValidateTokenAsync"/>/
/// <see cref="IntrospectTokenAsync"/> and travels in the request message; it has no
/// default, so it can never silently fall back to the caller's own token.
/// </remarks>
public sealed class TokenGrpcClient : IDisposable
{
    private static readonly TimeSpan ValidateDeadline = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan IntrospectDeadline = TimeSpan.FromSeconds(3);

    private readonly GrpcChannel? _ownedChannel;
    private readonly TokenService.TokenServiceClient _stub;
    private readonly Func<string?> _tokenAccessor;

    /// <summary>
    /// Constructs the token gRPC transport from <paramref name="client"/>'s exposed
    /// internal seam, sharing its session exactly as <see cref="AxiamGrpcAuthzClient"/>
    /// does — this constructor never modifies <see cref="AxiamClient"/> itself.
    /// </summary>
    /// <param name="client">The already-constructed REST <see cref="AxiamClient"/> whose
    /// session (RefreshGuard/tenant/token) this gRPC transport shares.</param>
    /// <param name="grpcTarget">
    /// The gRPC endpoint. Defaults to <paramref name="client"/>'s own REST
    /// <c>BaseUrl</c> when omitted.
    /// </param>
    public TokenGrpcClient(AxiamClient client, Uri? grpcTarget = null)
    {
        ArgumentNullException.ThrowIfNull(client);

        _tokenAccessor = () => client.CurrentAccessToken;

        // A Func<bool>, not a bool snapshot — see AxiamGrpcAuthzClient's identical
        // construction for why (N4.4 can release the device credential later).
        var interceptor = new AuthInterceptor(_tokenAccessor, client.TenantId, client.RefreshGuard, refreshExempt: () => client.HasStaticBearerToken);
        // §6.1: forward the same mTLS client identity the REST transport uses so both
        // transports of this one AxiamClient present the same client certificate.
        _ownedChannel = AxiamGrpcChannel.Create(grpcTarget ?? client.BaseUrl, client.CustomCaPem, client.ClientCertificatePem, client.ClientKeyPem);
        CallInvoker interceptedInvoker = _ownedChannel.Intercept(interceptor);
        _stub = new TokenService.TokenServiceClient(interceptedInvoker);
    }

    /// <summary>
    /// Test-only seam: builds over an already-intercepted <see cref="CallInvoker"/>,
    /// bypassing the public constructor's strict-TLS <see cref="GrpcChannel"/>
    /// construction. Mirrors <see cref="AxiamGrpcAuthzClient"/>'s own test constructor.
    /// </summary>
    internal TokenGrpcClient(CallInvoker invoker, Func<string?> tokenAccessor)
    {
        ArgumentNullException.ThrowIfNull(invoker);
        _ownedChannel = null;
        _stub = new TokenService.TokenServiceClient(invoker);
        _tokenAccessor = tokenAccessor ?? throw new ArgumentNullException(nameof(tokenAccessor));
    }

    /// <summary>
    /// <c>ValidateToken</c> (CONTRACT.md &#167;1.1.1, &#167;10.3): a lighter-weight check
    /// than <see cref="IntrospectTokenAsync"/> — signature, expiry and tenant, plus the
    /// &#167;10.1 rule 9 confirmation. On <c>UNAUTHENTICATED</c> (the CALLER's own token
    /// having expired), the shared <c>AuthInterceptor</c> drives exactly one shared-guard
    /// refresh and retries once (&#167;9.3) before this method ever observes a terminal
    /// failure.
    /// </summary>
    /// <param name="accessToken">The token being inspected — secret material, and a
    /// DIFFERENT credential from whichever one authenticates this call.</param>
    /// <param name="cancellationToken">Cancels the in-flight RPC.</param>
    /// <returns>Every field the response message defines.</returns>
    /// <exception cref="AuthError">
    /// No active session on this <see cref="AxiamClient"/> (no wire call, &#167;1.1.1 rule
    /// 2), or a terminal gRPC <c>UNAUTHENTICATED</c>.
    /// </exception>
    public async Task<TokenValidation> ValidateTokenAsync(Sensitive<string> accessToken, CancellationToken cancellationToken = default)
    {
        RequireCallerSession();

        var wire = new ValidateTokenRequest { AccessToken = accessToken.Reveal() };
        try
        {
            using AsyncUnaryCall<ValidateTokenResponse> call = _stub.ValidateTokenAsync(
                wire, deadline: DateTime.UtcNow.Add(ValidateDeadline), cancellationToken: cancellationToken);
            ValidateTokenResponse response = await call.ResponseAsync.ConfigureAwait(false);
            return new TokenValidation(
                response.Valid,
                response.SubjectId,
                response.TenantId,
                response.OrgId,
                response.Exp,
                ToTokenCnf(response.Cnf),
                response.TokenType);
        }
        catch (RpcException ex)
        {
            throw ErrorMapper.FromGrpcStatus(ex.StatusCode, DescriptionOf(ex));
        }
    }

    /// <summary>
    /// <c>IntrospectToken</c> (CONTRACT.md &#167;1.1.1, &#167;10.3): the RFC 7662 field set,
    /// including UMA permissions and X4 cross-domain provenance. Same
    /// precondition/UNAUTHENTICATED/single-flight-retry behaviour as
    /// <see cref="ValidateTokenAsync"/>.
    /// </summary>
    /// <param name="accessToken">The token being inspected.</param>
    /// <param name="cancellationToken">Cancels the in-flight RPC.</param>
    /// <returns>Every field the response message defines.</returns>
    /// <exception cref="AuthError">
    /// No active session on this <see cref="AxiamClient"/> (no wire call), or a terminal
    /// gRPC <c>UNAUTHENTICATED</c>.
    /// </exception>
    public async Task<TokenIntrospection> IntrospectTokenAsync(Sensitive<string> accessToken, CancellationToken cancellationToken = default)
    {
        RequireCallerSession();

        var wire = new IntrospectTokenRequest { AccessToken = accessToken.Reveal() };
        try
        {
            using AsyncUnaryCall<IntrospectTokenResponse> call = _stub.IntrospectTokenAsync(
                wire, deadline: DateTime.UtcNow.Add(IntrospectDeadline), cancellationToken: cancellationToken);
            IntrospectTokenResponse response = await call.ResponseAsync.ConfigureAwait(false);
            return new TokenIntrospection(
                response.Active,
                response.Sub,
                response.TenantId,
                response.OrgId,
                response.Iss,
                response.Iat,
                response.Exp,
                response.Jti,
                response.Scope,
                response.ClientId,
                response.TokenType,
                ToTokenCnf(response.Cnf),
                response.Permissions.Select(p => new RptPermission(p.ResourceId, p.ResourceScopes.ToList(), p.Exp)).ToList(),
                response.ExtExchangeIss);
        }
        catch (RpcException ex)
        {
            throw ErrorMapper.FromGrpcStatus(ex.StatusCode, DescriptionOf(ex));
        }
    }

    /// <summary>The channel is shut down with the client — a no-op when this instance was
    /// built over a caller-owned <see cref="CallInvoker"/> (the internal test seam).</summary>
    public void Dispose() => _ownedChannel?.Dispose();

    /// <summary>&#167;1.1.1 rule 2 (mirrors &#167;1.1 rule 3, applied here): both operations
    /// need a caller token; with none, the SDK raises client-side, WITHOUT a wire call.</summary>
    private void RequireCallerSession()
    {
        if (_tokenAccessor() is null)
        {
            throw new AuthError("no active session — call LoginAsync() before ValidateTokenAsync()/IntrospectTokenAsync()");
        }
    }

    /// <summary>
    /// Proto3 message-typed fields carry natural presence: <c>null</c> when the response
    /// omitted <c>cnf</c> entirely (an unbound token), a real (possibly all-default)
    /// value when it did not — &#167;1.1.1 rule 3 / &#167;10.3 rule 3's distinction, preserved
    /// rather than collapsed.
    /// </summary>
    private static TokenCnf? ToTokenCnf(CnfClaim? cnf) => cnf is null ? null : new TokenCnf(cnf.X5TS256, cnf.Jkt);

    private static string DescriptionOf(RpcException ex) => ex.Status.Detail is { Length: > 0 } detail ? detail : ex.StatusCode.ToString();
}
