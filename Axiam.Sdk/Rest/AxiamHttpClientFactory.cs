using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Axiam.Sdk.Rest;

/// <summary>
/// Builds the SDK-owned <see cref="HttpClient"/> (D-09 default path) and configures the
/// <c>IHttpClientFactory</c>-compatible alternative path (D-09 alt path, wired up by a
/// later plan's <c>AddAxiam()</c>). Both paths guarantee the CONTRACT.md &#167;4
/// persistent cookie jar and the &#167;6 no-TLS-bypass policy — a caller-supplied handler
/// can never silently drop either guarantee (client-override safety, Java D-27 analog).
/// </summary>
public static class AxiamHttpClientFactory
{
    /// <summary>
    /// Creates the SDK's own, owned <see cref="HttpClient"/> over a fresh
    /// <see cref="HttpClientHandler"/> configured by <see cref="CreatePrimaryHandler"/>
    /// (&#167;4 cookie jar + &#167;6 no-TLS-bypass).
    /// </summary>
    public static HttpClient CreateOwned(byte[]? customCaPem) => new(CreatePrimaryHandler(customCaPem));

    /// <summary>
    /// mTLS overload of <see cref="CreateOwned(byte[])"/> (CONTRACT.md &#167;6.1): builds the
    /// SDK-owned <see cref="HttpClient"/> additionally presenting the given PEM
    /// client-certificate identity for mutual-TLS client authentication.
    /// </summary>
    public static HttpClient CreateOwned(byte[]? customCaPem, byte[]? clientCertPem, byte[]? clientKeyPem)
        => new(CreatePrimaryHandler(customCaPem, clientCertPem, clientKeyPem));

    /// <summary>
    /// Builds the primary <see cref="HttpClientHandler"/> with <c>UseCookies = true</c>
    /// and a private <see cref="CookieContainer"/> (&#167;4). When
    /// <paramref name="customCaPem"/> is supplied, an ADDITIVE chain-trust-store
    /// callback is installed — it never returns <c>true</c> unconditionally (&#167;6/
    /// SC#4: no TLS-bypass surface exists anywhere in this SDK). Exposed separately from
    /// <see cref="CreateOwned(byte[])"/> so <c>AxiamClient</c> can compose this handler as the
    /// innermost link of its own <c>AxiamHttpMessageHandler</c> chain while still
    /// sharing the exact same cookie-jar/TLS configuration.
    /// </summary>
    /// <remarks>
    /// When <paramref name="clientCertPem"/>/<paramref name="clientKeyPem"/> are supplied
    /// (CONTRACT.md &#167;6.1), the PEM client-certificate identity is added to
    /// <see cref="HttpClientHandler.ClientCertificates"/> for mutual-TLS client
    /// authentication. This is a distinct code path from the additive custom-CA
    /// server-trust callback above: presenting a client certificate NEVER relaxes strict
    /// server verification (&#167;6.1 rule 2), and this method installs no permissive
    /// server-validation delegate.
    /// </remarks>
    /// <param name="customCaPem">Optional PEM custom-CA bytes for additive server-trust (&#167;6).</param>
    /// <param name="clientCertPem">Optional PEM client-certificate chain for mTLS (&#167;6.1). MUST accompany <paramref name="clientKeyPem"/>.</param>
    /// <param name="clientKeyPem">Optional PEM private key (PKCS#8/PKCS#1) for mTLS (&#167;6.1). MUST accompany <paramref name="clientCertPem"/>.</param>
    public static HttpClientHandler CreatePrimaryHandler(byte[]? customCaPem, byte[]? clientCertPem = null, byte[]? clientKeyPem = null)
    {
        var handler = new HttpClientHandler
        {
            UseCookies = true,
            CookieContainer = new CookieContainer(),
            // SDK-17: never auto-follow redirects. .NET strips `Authorization` on a
            // cross-origin redirect but NOT the SDK's custom `X-Tenant-Id`/`X-CSRF-Token`
            // headers (added by AxiamHttpMessageHandler), so a downgrade/cross-origin 3xx
            // could silently re-send them to an untrusted host. The SDK never relies on
            // auto-redirect: auth endpoints are POSTs that must not 3xx-redirect, and no
            // SDK call path expects a transparent redirect — a 3xx surfaces to the caller
            // instead of being followed blindly.
            AllowAutoRedirect = false,
        };

        if (customCaPem is not null && customCaPem.Length > 0)
        {
            // net8.0 TFM: `new X509Certificate2(byte[])` is NOT obsolete on this target
            // (SYSLIB0057's obsolete marking was introduced starting with the .NET 9
            // reference assemblies; net8.0's reference assembly predates it, so no build
            // warning is produced when targeting net8.0-only per D-01) — this resolves
            // 21-RESEARCH.md Open Question 3 / Assumption A2 without a suppression being
            // strictly required. `X509CertificateLoader` (the newer, non-obsolete .NET
            // 9+ API) has no net8.0-compatible surface, so it is not used here.
            X509Certificate2 customCa;
            try
            {
                customCa = new X509Certificate2(customCaPem);
            }
            catch (CryptographicException ex)
            {
                // §6: "If a non-PEM format is passed, the SDK MUST return a clear error
                // at construction time" — surfaced here, before any network activity,
                // rather than as an opaque low-level exception at first-use.
                throw new ArgumentException(
                    "customCaPem must be PEM-encoded certificate bytes for the issuing CA (CONTRACT.md §6).",
                    nameof(customCaPem),
                    ex);
            }

            handler.ServerCertificateCustomValidationCallback = (_, cert, chain, _) => // additive CustomTrustStore chain-trust callback (never `=> true`)
            {
                if (cert is null || chain is null)
                {
                    return false;
                }

                // Adds ONE trusted CA to the chain — this is NOT a bypass: unknown or
                // mismatched certificates still fail verification. There is no branch
                // here (or anywhere else in this SDK) that returns `true`
                // unconditionally — the exact §6/SC#4-prohibited shape CI's grep gate
                // (plan 21-07) scans for.
                chain.ChainPolicy.CustomTrustStore.Add(customCa);
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                return chain.Build(cert);
            };
        }
        // No `else` branch sets a validation callback to anything permissive — the
        // default system trust store verification applies untouched (the only
        // callback assignment anywhere in this file is the additive CustomTrustStore
        // path above).

        X509Certificate2? clientCert = BuildClientCertificate(clientCertPem, clientKeyPem);
        if (clientCert is not null)
        {
            // §6.1: present a client identity for mutual TLS. This is a purely additive
            // client-side credential — it configures what the client OFFERS, and never
            // touches how the SERVER's certificate is verified (no server-verification
            // callback is set here), so strict server verification (§6.1 rule 2) stays
            // fully intact.
            handler.ClientCertificates.Add(clientCert);
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
        }

        return handler;
    }

    /// <summary>
    /// Re-applies the SDK's cookie jar (&#167;4) and pooled-connection lifetime settings
    /// onto a <see cref="SocketsHttpHandler"/> registered via <c>IHttpClientFactory</c>/
    /// <c>AddHttpClient</c> (D-09 alt path, wired up by a later plan) — even if the
    /// caller supplied their own handler instance, client-override safety means the
    /// cookie jar can never be silently dropped (breaking post-login). The only
    /// <see cref="SocketsHttpHandler.SslOptions"/> this method ever writes is the
    /// &#167;6.1 mTLS client identity (<see cref="SslClientAuthenticationOptions.ClientCertificates"/>,
    /// what the client OFFERS) when a client certificate is configured — it never sets
    /// <see cref="SslClientAuthenticationOptions.RemoteCertificateValidationCallback"/> or
    /// otherwise weakens server verification.
    /// </summary>
    public static void ConfigureFactoryHandler(SocketsHttpHandler handler, byte[]? clientCertPem = null, byte[]? clientKeyPem = null)
    {
        ArgumentNullException.ThrowIfNull(handler);
        handler.UseCookies = true; // re-applied even if the caller supplied their own SocketsHttpHandler
        handler.CookieContainer = new CookieContainer();
        handler.PooledConnectionLifetime = TimeSpan.FromMinutes(15);
        // SDK-17: same rationale as CreatePrimaryHandler — re-applied on the alt path so a
        // caller-supplied SocketsHttpHandler can never re-enable auto-redirect and leak the
        // SDK's custom X-Tenant-Id/X-CSRF-Token headers across a cross-origin 3xx.
        handler.AllowAutoRedirect = false;
        // Same rule as CreatePrimaryHandler's additive CustomTrustStore callback: never
        // set an unconditional-true validation callback here.

        X509Certificate2? clientCert = BuildClientCertificate(clientCertPem, clientKeyPem);
        if (clientCert is not null)
        {
            // §6.1: present the client identity for mutual TLS on the SocketsHttpHandler
            // alt path. This only sets ClientCertificates (what the client OFFERS) on
            // SslOptions; it never assigns RemoteCertificateValidationCallback, so strict
            // server verification (§6.1 rule 2) is untouched.
            handler.SslOptions.ClientCertificates = new X509CertificateCollection { clientCert };
        }
    }

    /// <summary>
    /// Builds the mutual-TLS client identity (CONTRACT.md &#167;6.1) from a PEM certificate
    /// chain plus PEM private key, or returns <c>null</c> when neither is supplied.
    /// Enforces &#167;6.1's baseline: a non-PEM value, or supplying exactly one of the two,
    /// surfaces a clear <see cref="ArgumentException"/> at construction time.
    /// </summary>
    private static X509Certificate2? BuildClientCertificate(byte[]? clientCertPem, byte[]? clientKeyPem)
    {
        bool hasCert = clientCertPem is not null && clientCertPem.Length > 0;
        bool hasKey = clientKeyPem is not null && clientKeyPem.Length > 0;

        if (!hasCert && !hasKey)
        {
            return null;
        }

        if (hasCert != hasKey)
        {
            // §6.1: the mandatory baseline is a PEM cert chain PLUS a PEM private key —
            // supplying only one is a misconfiguration surfaced before any network activity.
            throw new ArgumentException(
                "Client-certificate mTLS requires BOTH ClientCertificatePem and ClientKeyPem (CONTRACT.md §6.1); exactly one was supplied.",
                hasCert ? nameof(clientKeyPem) : nameof(clientCertPem));
        }

        try
        {
            // §6.1: PEM cert+key is the mandatory input format. The raw key bytes are used
            // only to construct the X509Certificate2 identity here and are never retained,
            // logged, or exposed by this method.
            return X509Certificate2.CreateFromPem(
                Encoding.UTF8.GetString(clientCertPem!),
                Encoding.UTF8.GetString(clientKeyPem!));
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            // §6.1 rule 1 (consistent with §6): "A non-PEM value MUST produce a clear error
            // at construction time." Surfaced here rather than as an opaque low-level
            // exception at first TLS handshake.
            throw new ArgumentException(
                "ClientCertificatePem must be a PEM-encoded certificate chain and ClientKeyPem a PEM-encoded PKCS#8/PKCS#1 private key (CONTRACT.md §6.1).",
                nameof(clientCertPem),
                ex);
        }
    }
}
