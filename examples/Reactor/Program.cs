using System.Globalization;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;
using Axiam.Sdk.Reactor;
using RabbitMQ.Client;

namespace Reactor;

/// <summary>
/// A working reactor (CONTRACT.md §22): subscribe to hook events on the AMQP bus, decide,
/// and answer allow / deny / mutate under a signed, timeout-bounded, field-allow-listed
/// protocol.
///
/// <para>This one does two jobs, one per event:</para>
/// <list type="bullet">
/// <item><description><c>token.pre_issue</c> — <b>enrich</b>. Adds a cost centre and a
/// department claim under the <c>ext.</c> namespace, which is the entire allow-list for
/// this event. Nothing outside <c>ext.</c> is reachable: a reply setting <c>sub</c> is
/// refused by the server exactly as a forged one is.</description></item>
/// <item><description><c>login.post_auth</c> — <b>veto or step up</b>. Denies an embargoed
/// region outright, and demands MFA for an administrative sign-in. This event is veto-only,
/// so no patch is possible here at all.</description></item>
/// </list>
///
/// <para>
/// What the runtime does for you, before this handler ever runs: rejects
/// <c>key_version &lt; 2</c>, verifies the HMAC over the canonical bytes, checks freshness
/// in both directions, and checks the nonce. What it does after: signs the reply with the
/// same tenant subkey and publishes it to the delivery's <c>reply_to</c>, with
/// <c>correlation_id</c> inside the signed body — which is the field the server actually
/// authenticates.
/// </para>
///
/// <para>
/// <b>Throwing is a supported answer.</b> If your backing service is down, let the exception
/// out: the runtime publishes <em>nothing</em>, and the registration's
/// <c>failure_policy</c> (<c>fail_open</c> for <c>token.pre_issue</c>, <c>fail_closed</c>
/// for <c>login.post_auth</c>) decides what that costs. Returning <c>allow</c> because you
/// could not reach your fraud service is how a <c>fail_closed</c> setting gets defeated from
/// inside the process that was supposed to honour it.
/// </para>
///
/// <para>
/// <b>Register first.</b> The queue this consumes is declared by the <em>server</em>, from a
/// registration made through <c>POST /api/v1/reactors</c>. This process never declares or
/// binds anything:
/// </para>
/// <code>
/// POST /api/v1/reactors
/// {
///   "name": "claims-enricher",
///   "events": ["token.pre_issue", "login.post_auth"],
///   "mode": "intercept",
///   "priority": 10,
///   "timeout_ms": 500
/// }
/// </code>
/// <para>
/// Omitting <c>failure_policy</c> there gives the strictest default among the events named —
/// <c>fail_closed</c>, because this registration can veto a login.
/// </para>
/// </summary>
public static class Program
{
    private const string EmbargoedRegion = "KP";

    /// <summary>Runs the reactor until the process is interrupted.</summary>
    /// <returns>A task that completes when the process is cancelled.</returns>
    public static async Task Main()
    {
        // §8b: amqps:// only. HMAC gives authenticity across broker hops; it does not give
        // confidentiality, and a reactor reply is an instruction to change a token. There is
        // no verification-skip switch in this SDK and no plaintext fallback — a failed
        // amqps:// connection is an error to surface, not a condition to work around.
        string amqpUri = Required("AXIAM_AMQP_URI");
        if (!amqpUri.StartsWith("amqps://", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "AXIAM_AMQP_URI must be amqps:// (CONTRACT.md §8b) — there is no plaintext fallback");
        }

        Guid tenantId = Guid.Parse(Required("AXIAM_TENANT_ID"));
        Guid reactorId = Guid.Parse(Required("AXIAM_REACTOR_ID"));

        // §22.12: the tenant AMQP signing key is a credential. Wrapped in Sensitive so it
        // cannot leak through ToString(), System.Text.Json, or a reconnect diagnostic. Fetch
        // it from the management API — never hardcode it, and never log it at any level.
        Sensitive<byte[]> subkey = Sensitive<byte[]>.Wrap(
            Convert.FromHexString(Required("AXIAM_AMQP_SUBKEY_HEX")));

        var factory = new ConnectionFactory
        {
            Uri = new Uri(amqpUri),
            AutomaticRecoveryEnabled = true,
            // Sequential dispatch: this handler is not written to be re-entrant.
            ConsumerDispatchConcurrency = 1,
        };

        using var stopping = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            stopping.Cancel();
        };

        await using IConnection connection = await factory.CreateConnectionAsync(CancellationToken.None);
        await using IChannel channel = await connection.CreateChannelAsync();

        await using ReactorServer server = await ReactorServer.ReactorServeAsync(new ReactorServeOptions
        {
            Channel = channel,
            TenantId = tenantId,
            SigningKey = subkey,
            // The queue belongs to THIS registration. The runtime derives it from our own
            // reactor id and consumes it; it declares nothing and binds nothing (§22.1).
            ReactorId = reactorId,
            Handler = DecideAsync,
        });

        Console.WriteLine($"axiam reactor serving {server.Queue} — Ctrl+C to stop");

        try
        {
            await Task.Delay(Timeout.Infinite, stopping.Token);
        }
        catch (OperationCanceledException)
        {
            // §18: disposing the server (the `await using` above) cancels the consumer and
            // drains what is in flight before the channel closes.
            Console.WriteLine("draining in-flight events…");
        }
    }

    /// <summary>The decision function. One event in, one of three answers out.</summary>
    private static Task<ReactorDecision> DecideAsync(ReactorEvent reactorEvent, CancellationToken cancellationToken) =>
        Task.FromResult(reactorEvent.Event switch
        {
            ReactorEvents.TokenPreIssue => EnrichToken(reactorEvent),
            ReactorEvents.LoginPostAuth => ScreenLogin(reactorEvent),

            // A reactor is only ever dispatched events it registered for, so this arm means
            // the registration and the code have drifted. Allow rather than deny: refusing an
            // operation because our own switch is stale would be an outage caused by a typo.
            _ => ReactorDecision.Allowed(),
        });

    private static ReactorDecision EnrichToken(ReactorEvent reactorEvent)
    {
        if (Text(reactorEvent, "sub") is not { } subject)
        {
            return ReactorDecision.Allowed();
        }

        // An earlier reactor in the chain may already have set claims. This is read-only
        // context: the server merges, later priority winning a contested key, so echoing
        // these back is not how a field is preserved.
        IReadOnlyDictionary<string, string> alreadySet = reactorEvent.PriorPatch();

        var patch = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!alreadySet.ContainsKey("ext.cost_center"))
        {
            patch["ext.cost_center"] = CostCentreFor(subject);
        }

        patch["ext.department"] = "engineering";

        // `ext.` is the whole allow-list here — `sub`, `aud`, `exp`, `scope` and every other
        // standard claim are unreachable, which is the point. Note this SDK never trims a
        // patch for you: a forbidden key is sent as written and refused by the server, so you
        // find out.
        return ReactorDecision.Mutated(patch);
    }

    private static ReactorDecision ScreenLogin(ReactorEvent reactorEvent)
    {
        if (Text(reactorEvent, "region") == EmbargoedRegion)
        {
            // The reason is audited. A deny with no reason still denies; the reason is for
            // the audit trail, not for the decision.
            return ReactorDecision.Denied("sign-in from an embargoed region");
        }

        if (Text(reactorEvent, "is_admin") == "true")
        {
            // allow + require_mfa: proceed only after step-up. Valid on login.post_auth ONLY —
            // the server refuses it anywhere else before it even looks at the decision. Sticky
            // across the chain: once any reactor demands step-up, no later one can clear it.
            //
            // A SAML or OIDC sign-in has no step-up branch, so this answer FAILS those logins
            // rather than being silently dropped. If your tenant federates, deny here and
            // drive enrolment out of band instead.
            return ReactorDecision.AllowRequiringStepUp();
        }

        return ReactorDecision.Allowed();
    }

    private static string CostCentreFor(string subject) =>
        Math.Abs(StringComparer.Ordinal.GetHashCode(subject) % 100).ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Reads a payload field as text. The payload is a plain JSON object — never a
    /// credential, a token or a signing key, because a reactor is told what is being decided,
    /// not handed the means to act on it elsewhere.
    /// </summary>
    private static string? Text(ReactorEvent reactorEvent, string field) =>
        reactorEvent.Payload[field] is JsonValue value && value.TryGetValue(out string? text) ? text : null;

    private static string Required(string key) =>
        Environment.GetEnvironmentVariable(key) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"{key} must be set");
}
