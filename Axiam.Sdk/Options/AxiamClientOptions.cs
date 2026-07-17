namespace Axiam.Sdk.Options;

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

    /// <summary>TCP connect timeout for the SDK-owned <see cref="System.Net.Http.HttpClient"/>.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Overall per-request timeout for the SDK-owned <see cref="System.Net.Http.HttpClient"/>.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Idempotent-only bounded exponential backoff + jitter (Claude's Discretion,
    /// 21-RESEARCH.md/21-CONTEXT.md): state-changing requests (login/refresh/logout)
    /// never auto-retry. Reserved config surface for a future read-only-retry wrapper
    /// around <c>AuthzRestClient</c>'s idempotent <c>GET</c>-shaped checks — not yet
    /// wired into any call path by this plan's tasks.
    /// </summary>
    public int MaxRetryAttempts { get; init; } = 3;

    /// <summary>Base delay for the bounded exponential backoff described above.</summary>
    public TimeSpan RetryBaseDelay { get; init; } = TimeSpan.FromMilliseconds(200);

    /// <summary>Upper bound for the bounded exponential backoff described above.</summary>
    public TimeSpan RetryMaxDelay { get; init; } = TimeSpan.FromSeconds(5);
}
