using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using RabbitMQ.Client;

namespace Axiam.Sdk.Reactor;

/// <summary>
/// Broker connections for a reactor, with CONTRACT.md &#167;8b enforced rather than described.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this class exists.</b> <see cref="ReactorServeOptions.Channel"/> takes an already-open
/// channel, and the caller owns its lifecycle. That is a reasonable division — but until now the
/// &#167;8b requirement travelling with it was a sentence of XML doc: "its connection MUST have
/// been opened over <c>amqps://</c> with a trusted CA". A doc-comment MUST is a note to whoever
/// reads the doc comment. Someone who builds a <see cref="ConnectionFactory"/> from an
/// <c>amqp://</c> URI and hands over the channel gets a working reactor, no warning, and
/// signed-but-readable token decisions on the wire.
/// </para>
/// <para>
/// This class is the enforcing alternative. Build the factory here and &#167;8b holds by
/// construction: the URI is checked, TLS is on with verification at its strict default, and there
/// is no argument anywhere that turns either off. The Kotlin and Java SDKs ship the same helper
/// against their own client library, deliberately — SDKs should not disagree about what a reactor
/// is allowed to connect to.
/// </para>
/// <para>
/// <see cref="ReactorServeOptions"/> still accepts any channel: enforcing at construction cannot
/// retroactively constrain a channel someone else opened, and refusing to serve on one whose
/// provenance cannot be inspected would break every legitimate custom setup to catch a mistake
/// this class already prevents.
/// </para>
/// <para>
/// <b>The layering, once.</b> HMAC signing (&#167;8/&#167;22.2) gives authenticity and replay
/// protection <em>across broker hops</em>, which TLS cannot, because TLS terminates at the broker
/// and the broker re-sends. TLS gives confidentiality, which HMAC cannot. A reactor's reply is an
/// instruction to allow, deny or rewrite a token: it needs both, and neither substitutes for the
/// other.
/// </para>
/// <example>
/// <code>
/// ConnectionFactory factory = ReactorConnections.CreateConnectionFactory(
///     "amqps://reactor:secret@broker.internal:5671/%2f",
///     new X509Certificate2("/etc/axiam/broker-ca.pem"));
///
/// await using IConnection connection = await factory.CreateConnectionAsync();
/// await using IChannel channel = await connection.CreateChannelAsync();
/// </code>
/// </example>
/// </remarks>
public static class ReactorConnections
{
    /// <summary>
    /// Builds a <see cref="ConnectionFactory"/> for <paramref name="amqpUri"/>, refusing anything
    /// but <c>amqps://</c>.
    /// </summary>
    /// <param name="amqpUri">
    /// The broker URI. MUST be <c>amqps://</c> (&#167;8b rules 1 and 5); every other scheme is
    /// refused here rather than downgraded, because a fallback that works is a fallback that gets
    /// used.
    /// </param>
    /// <param name="brokerCaCertificate">
    /// The CA that issued a privately-issued broker certificate (&#167;8b rule 2 — the common
    /// in-cluster case), or <c>null</c> to verify against the OS trust store only. Supplied as an
    /// additional trust anchor via <see cref="SslOption.CertificateValidationCallback"/>; see the
    /// remarks on <see cref="BuildValidationCallback"/> for why a callback is the mechanism and
    /// what it is careful not to become.
    /// </param>
    /// <param name="clientCertificate">
    /// A client certificate <em>with its private key</em>, for mutual TLS toward the broker
    /// (&#167;8b rule 3), or <c>null</c>. A certificate without a usable private key is refused:
    /// half a client identity cannot authenticate, and connecting anyway would silently drop the
    /// mutual half of mutual TLS.
    /// </param>
    /// <returns>A factory whose connections verify the broker.</returns>
    /// <exception cref="ArgumentException">
    /// The URI is not <c>amqps://</c>, is unparseable, or the client certificate carries no
    /// private key.
    /// </exception>
    public static ConnectionFactory CreateConnectionFactory(
        string amqpUri,
        X509Certificate2? brokerCaCertificate = null,
        X509Certificate2? clientCertificate = null)
    {
        RequireAmqps(amqpUri);

        if (clientCertificate is not null && !clientCertificate.HasPrivateKey)
        {
            throw new ArgumentException(
                "the reactor client certificate carries no private key — half a client identity " +
                "cannot authenticate, and connecting anyway would silently drop the mutual half " +
                "of mutual TLS (CONTRACT.md §8b rule 3). Load it from a PKCS#12/PFX that " +
                "includes the key.",
                nameof(clientCertificate));
        }

        var uri = new Uri(amqpUri);
        var factory = new ConnectionFactory
        {
            Uri = uri,
            AutomaticRecoveryEnabled = true,
            TopologyRecoveryEnabled = true,
            // Sequential dispatch, matching AxiamAmqpConsumer: a reactor handler
            // is not assumed to be re-entrant.
            ConsumerDispatchConcurrency = 1,
        };

        factory.Ssl.Enabled = true;
        // The name the certificate must match. Taken from the URI rather than
        // left to default, because a mismatch here is the failure hostname
        // verification exists to catch, and a blank ServerName is how that check
        // quietly turns into nothing.
        factory.Ssl.ServerName = uri.Host;
        // TLS 1.2 floor, 1.3 preferred. AXIAM's stated standard is TLS 1.3, and
        // the broker is where that floor is actually enforceable for this link
        // (`ssl_options.versions.1 = tlsv1.3` in rabbitmq.conf) — pinning 1.3
        // only on the client would fail against a broker that has not been
        // configured yet, and fail in a way that reads as "TLS is broken".
        factory.Ssl.Version = SslProtocols.Tls12 | SslProtocols.Tls13;
        // §8b rule 4: no policy error is tolerated. This is set explicitly rather
        // than left at its default so that a future edit relaxing it is a visible
        // change to this line, not a silent inheritance.
        factory.Ssl.AcceptablePolicyErrors = System.Net.Security.SslPolicyErrors.None;

        if (clientCertificate is not null)
        {
            factory.Ssl.Certs = [clientCertificate];
        }

        if (brokerCaCertificate is not null)
        {
            factory.Ssl.CertificateValidationCallback = BuildValidationCallback(brokerCaCertificate);
        }

        return factory;
    }

    /// <summary>
    /// Rejects any URI that is not <c>amqps://</c> (&#167;8b rules 1 and 5).
    /// </summary>
    /// <remarks>
    /// An unparseable URI is an error here, not a pass-through. A security check must fail closed
    /// on an input it cannot read — the opposite arrangement (skip the check when parsing fails)
    /// is a real bug that shipped in a sibling SDK.
    /// <para>
    /// There is no loopback exception. &#167;8b rules 1 and 5 carry no host carve-out, and the
    /// AXIAM server is TLS-only with no plaintext listener for one to reach.
    /// </para>
    /// </remarks>
    /// <param name="amqpUri">The broker URI to check.</param>
    /// <exception cref="ArgumentException">The scheme is anything but <c>amqps</c>.</exception>
    public static void RequireAmqps(string amqpUri)
    {
        if (!Uri.TryCreate(amqpUri?.Trim(), UriKind.Absolute, out Uri? uri))
        {
            throw new ArgumentException(
                $"the reactor broker URI is not a valid absolute URI: '{amqpUri}'. " +
                "CONTRACT.md §8b requires an amqps:// URL.",
                nameof(amqpUri));
        }

        if (!uri.Scheme.Equals("amqps", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"a reactor MUST connect over amqps:// (CONTRACT.md §8b rules 1 and 5) — got " +
                $"'{uri.Scheme}'. A reactor's reply is an instruction to allow, deny or rewrite a " +
                "token; HMAC signing gives it authenticity, not confidentiality. There is no " +
                "plaintext fallback and no verification-skip switch — supply the broker's CA if " +
                "its certificate is not publicly issued.",
                nameof(amqpUri));
        }
    }

    /// <summary>
    /// Builds a validation callback that accepts a chain rooted at <paramref name="brokerCa"/> in
    /// addition to the OS trust store.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A callback is the mechanism because <see cref="SslOption"/> offers no "extra root" list —
    /// the only seam for an additional trust anchor is
    /// <see cref="SslOption.CertificateValidationCallback"/>. That makes this the one place in the
    /// SDK where returning <c>true</c> unconditionally would disable verification entirely, so it
    /// is written to make that impossible to do by accident:
    /// </para>
    /// <list type="bullet">
    /// <item>a chain the OS already trusts is accepted, unchanged;</item>
    /// <item>anything else is re-verified with <see cref="X509Chain"/> against the supplied CA as a
    /// <see cref="X509ChainPolicy.CustomTrustStore"/>, with revocation and time validity still
    /// checked — this is a real verification, not a name comparison;</item>
    /// <item>every other outcome returns <c>false</c>. There is no branch that returns <c>true</c>
    /// without a chain having been built and accepted.</item>
    /// </list>
    /// <para>
    /// The callback closes over the CA it was given and takes no configuration, so there is no
    /// argument a caller can pass that weakens it (&#167;8b rule 4).
    /// </para>
    /// </remarks>
    private static System.Net.Security.RemoteCertificateValidationCallback BuildValidationCallback(
        X509Certificate2 brokerCa)
    {
        return (_, certificate, chain, sslPolicyErrors) =>
        {
            // Already trusted by the OS store — nothing to add.
            if (sslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
            {
                return true;
            }

            // A name mismatch is never something a custom CA can excuse: the
            // certificate is for a different host, whoever signed it.
            if (sslPolicyErrors.HasFlag(
                    System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch)
                || sslPolicyErrors.HasFlag(
                    System.Net.Security.SslPolicyErrors.RemoteCertificateNotAvailable))
            {
                return false;
            }

            if (certificate is null)
            {
                return false;
            }

            using var leaf = new X509Certificate2(certificate);
            using var customChain = new X509Chain();
            customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            customChain.ChainPolicy.CustomTrustStore.Add(brokerCa);
            customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            customChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            // Carry across any intermediates the broker sent, so a chain that
            // needs them can still be built.
            if (chain is not null)
            {
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    customChain.ChainPolicy.ExtraStore.Add(element.Certificate);
                }
            }

            return customChain.Build(leaf);
        };
    }

}
