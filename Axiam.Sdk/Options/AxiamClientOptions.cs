namespace Axiam.Sdk.Options;

using Axiam.Sdk.Core;

/// <summary>
/// Typed, options-pattern configuration for <c>AxiamClient</c> (Claude's Discretion,
/// 21-RESEARCH.md/21-CONTEXT.md D-07). <see cref="BaseUrl"/> and <see cref="TenantId"/>
/// are <c>required</c> here for the future <c>AddAxiam()</c>/
/// <c>IOptions&lt;AxiamClientOptions&gt;</c> DI registration path (plan 21-06) —
/// <c>AxiamClient</c>'s own tenant-required constructor (this plan, SC#1) sources the
/// tenant/base-URL from its own explicit positional parameters instead, so SC#1's
/// compile-time guarantee never depends on whether an options object happens to be
/// supplied at all.
/// </summary>
public sealed record AxiamClientOptions
{
    /// <summary>Reserved for the future DI/options-pattern registration path (D-07,
    /// plan 21-06); <c>AxiamClient</c>'s own constructor (this plan) always uses its
    /// own <c>baseUrl</c> parameter as the source of truth, never this field.</summary>
    public required Uri BaseUrl { get; init; }

    /// <summary>Reserved for the future DI/options-pattern registration path (D-07,
    /// plan 21-06); <c>AxiamClient</c>'s own constructor (this plan) always uses its
    /// own <c>tenantId</c> parameter as the source of truth, never this field.</summary>
    public required string TenantId { get; init; }

    /// <summary>Organization UUID resolved by the real AXIAM login/refresh endpoints
    /// (beyond CONTRACT.md &#167;5's documented tenant-only minimum). Mutually exclusive
    /// with <see cref="OrgSlug"/> — set at most one.</summary>
    public Guid? OrgId { get; init; }

    /// <summary>Organization slug. Mutually exclusive with <see cref="OrgId"/> — set at
    /// most one.</summary>
    public string? OrgSlug { get; init; }

    /// <summary>
    /// PEM-encoded custom CA certificate bytes — the ONLY TLS escape hatch (CONTRACT.md
    /// &#167;6/SC#4): an ADDITIVE chain-trust-store entry alongside the system trust
    /// store, never a bypass. <c>null</c> (the default) uses the system trust store only.
    /// </summary>
    public byte[]? CustomCaPem { get; init; }

    /// <summary>
    /// PEM-encoded client-certificate chain presented for mutual-TLS (mTLS) client
    /// authentication (CONTRACT.md &#167;6.1): AXIAM binds this X.509 identity — signed by
    /// the tenant's organization CA — to a service account or IoT device. Applies to
    /// <b>both</b> the REST and gRPC transports of the same <c>AxiamClient</c>. Opt-in:
    /// <c>null</c> (the default) leaves the SDK's bearer-cookie behavior unchanged and
    /// presents no client certificate. MUST be set together with <see cref="ClientKeyPem"/>
    /// — supplying exactly one of the two is rejected with an <see cref="ArgumentException"/>
    /// at client construction. Presenting a client certificate NEVER relaxes strict server
    /// verification (&#167;6.1 rule 2); this is a separate code path from
    /// <see cref="CustomCaPem"/>'s server-trust callback.
    /// </summary>
    public byte[]? ClientCertificatePem { get; init; }

    /// <summary>
    /// PEM-encoded private key (PKCS#8 or PKCS#1) matching <see cref="ClientCertificatePem"/>,
    /// used for mutual-TLS client authentication (CONTRACT.md &#167;6.1). Secret material
    /// (&#167;7): it is never logged, serialized, or exposed via a public getter beyond this
    /// options record it is set on (mirrors <see cref="CustomCaPem"/>). MUST be set together
    /// with <see cref="ClientCertificatePem"/>; supplying exactly one of the two is rejected
    /// with an <see cref="ArgumentException"/> at client construction.
    /// </summary>
    public byte[]? ClientKeyPem { get; init; }

    /// <summary>How long a fetched JWKS document is trusted before <c>JwksVerifier</c>
    /// forces a refetch.</summary>
    public TimeSpan JwksCacheTtl { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The <c>iss</c> claim value local token verification requires (CONTRACT.md
    /// &#167;10.1 rule 5). CONDITIONAL and unset by default: <c>null</c> means no issuer
    /// check is performed at all; once set, a token whose <c>iss</c> differs &#8212; or
    /// which carries no <c>iss</c> &#8212; is rejected. There is no default value and no
    /// hardcoded AXIAM issuer anywhere in this SDK; supply your deployment's own issuer.
    /// </summary>
    public string? ExpectedIssuer { get; init; }

    /// <summary>
    /// The <c>aud</c> value local token verification requires (CONTRACT.md &#167;10.1
    /// rule 6). CONDITIONAL and unset by default: <c>null</c> means no audience check is
    /// performed at all; once set, a token whose <c>aud</c> does not contain it &#8212;
    /// including a token with no <c>aud</c> at all &#8212; is rejected. An application
    /// guarding a user-facing resource server should generally expect <c>axiam:user</c>;
    /// it is not defaulted, because a service-to-service guard legitimately expects a
    /// different audience.
    /// </summary>
    public string? ExpectedAudience { get; init; }

    /// <summary>TCP connect timeout for the SDK-owned <see cref="System.Net.Http.HttpClient"/>.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Overall per-request timeout for the SDK-owned <see cref="System.Net.Http.HttpClient"/>.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Attempt cap for the CONTRACT.md &#167;16 bounded read-only retry policy.
    /// Defaults to 3 (1 initial + 2 retries).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>This is now wired.</strong> Until D5 this property — and the two below —
    /// were a "reserved config surface ... not yet wired into any call path", so the SDK
    /// performed no read-only retries at all while presenting three knobs that looked
    /// like it did.
    /// </para>
    /// <para>
    /// <strong>Values above the contract's are clamped down, not honored.</strong>
    /// &#167;16.1 permits an SDK to <em>lower</em> the attempt cap or disable retry
    /// outright, never to raise it: a caller who could raise it turns one client into
    /// the thundering herd this policy exists to prevent, and the whole point of &#167;16
    /// is eleven SDKs agreeing on one table. Setting 10 gets you 3; setting 1 gets you 1.
    /// Use <see cref="RetryEnabled"/> to turn retrying off.
    /// </para>
    /// </remarks>
    public int MaxRetryAttempts { get; init; } = 3;

    /// <summary>
    /// Base delay for the &#167;16 backoff. Defaults to 200ms; a larger value is clamped
    /// down to it, for the reason given on <see cref="MaxRetryAttempts"/>.
    /// </summary>
    public TimeSpan RetryBaseDelay { get; init; } = TimeSpan.FromMilliseconds(200);

    /// <summary>
    /// Ceiling on any single &#167;16 backoff. Defaults to 5s; a larger value is clamped
    /// down to it, for the reason given on <see cref="MaxRetryAttempts"/>.
    /// </summary>
    public TimeSpan RetryMaxDelay { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Enables the CONTRACT.md &#167;16 bounded read-only retry policy.
    /// <strong>Default: <c>true</c>.</strong>
    /// </summary>
    /// <remarks>
    /// Set <c>false</c> to make every operation exactly one attempt. That is the right
    /// choice for a caller who owns their own retry layer — they know their deadline and
    /// this SDK does not — but it is not a way to make failures quieter: a transient
    /// <c>NetworkError</c> simply surfaces immediately.
    /// </remarks>
    public bool RetryEnabled { get; init; } = true;

    /// <summary>
    /// Enables the CONTRACT.md &#167;17 client-side decision memo.
    /// <strong>Default: <see cref="TimeSpan.Zero"/>, which means disabled</strong> — not
    /// "cache for zero time".
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>What you are accepting.</strong> The staleness bound is this TTL, <em>in
    /// both directions</em>. A grant revoked on the server can still read as allowed for
    /// up to the TTL, and a grant just added can still read as denied for up to the TTL.
    /// </para>
    /// <para>
    /// <strong>Reads-your-own-writes is not guaranteed.</strong> An admin UI that grants
    /// a role and immediately re-checks is the case that breaks, and it breaks silently.
    /// If that is your workload, leave this off.
    /// </para>
    /// <para>
    /// Clamped to 5 seconds rather than rejected. Allows and denies are memoized
    /// identically (asymmetric caching leaks the outcome through latency), failures are
    /// never memoized, and the memo is cleared on any credential change.
    /// </para>
    /// </remarks>
    public TimeSpan DecisionMemoTtl { get; init; } = TimeSpan.Zero;

    /// <summary>
    /// Installs a CONTRACT.md &#167;19 telemetry sink.
    /// </summary>
    /// <remarks>
    /// It receives request start/end, &#167;16 retry and &#167;9 refresh events, so
    /// metrics can be wired without this package depending on any metrics library. A hook
    /// that throws cannot fail the operation that fired it (&#167;19.2 rule 2), and no
    /// event payload can carry a token — the event hierarchy is closed with fixed
    /// property lists (&#167;19.2 rule 3). It is invoked on the calling task, so it must
    /// not block.
    /// </remarks>
    public TelemetryHook? TelemetryHook { get; init; }

    /// <summary>
    /// The relying party's OAuth2 <c>client_id</c> (CONTRACT.md &#167;12.1), used on every
    /// &#167;12 grant and matched against the ID token's <c>aud</c>/<c>azp</c> (&#167;12.4
    /// rule 4). Required before calling any &#167;12 operation other than
    /// <c>OidcDiscoverAsync</c> — client_id comes from client configuration, not a
    /// per-call argument (&#167;12 T1 reference judgment call 21).
    /// </summary>
    public string? OidcClientId { get; init; }

    /// <summary>
    /// A confidential client's <c>client_secret</c> (CONTRACT.md &#167;12.1). Omit for a
    /// public client: <c>LoginClientCredentialsAsync</c>, <c>IntrospectAsync</c>, and
    /// <c>RevokeAsync</c> then throw <see cref="Core.AuthError"/>, client-side with no wire
    /// call (&#167;12.1 note 4 — a public client cannot call them). Held behind
    /// <see cref="Core.Sensitive{T}"/> internally once the client is constructed.
    /// </summary>
    public string? OidcClientSecret { get; init; }

    /// <summary>
    /// The OIDC discovery-document cache TTL. Floored at 5 minutes per CONTRACT.md
    /// &#167;12.3 rule 6 — a smaller configured value is silently raised to the floor. The
    /// default (5 minutes) already satisfies the floor.
    /// </summary>
    public TimeSpan OidcDiscoveryTtl { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The permitted ID-token clock skew, in seconds, for the <c>exp</c>/<c>iat</c>/
    /// <c>nbf</c> checks (CONTRACT.md &#167;12.4 rule 5). Clamped to [1, 60] — the contract
    /// forbids configuring it above 60 seconds; a non-positive or larger value falls back
    /// to the 60-second default rather than being honored.
    /// </summary>
    public int OidcClockSkewSeconds { get; init; } = 60;
}
