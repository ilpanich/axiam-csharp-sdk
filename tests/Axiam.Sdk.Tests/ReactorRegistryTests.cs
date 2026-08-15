using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Axiam.Sdk.Reactor;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// The &#167;22.5 event registry, the &#167;22.7 hot-path exclusion, and &#167;22.8's
/// failure-policy composition and budget constants.
///
/// <para>
/// The &#167;22.7 test is the load-bearing one here, and it is deliberately written against
/// the reflected constant list rather than against a comment: "no SDK may present them as
/// such" is a MUST NOT, and a MUST NOT that nothing checks is a sentence.
/// </para>
/// </summary>
[Trait("Category", "Fast")]
public class ReactorRegistryTests
{
    // ---- §22.5 the namespace-prefix rule -----------------------------------

    [Fact]
    public void TokenPreIssue_AdmitsTheExtNamespaceAndNothingElse()
    {
        ReactorEventSpec spec = ReactorEvents.Spec(ReactorEvents.TokenPreIssue)!;

        Assert.True(spec.PatchFieldAllowed("ext.department"));
        Assert.True(spec.PatchFieldAllowed("ext.a.b.c"));
        Assert.True(spec.PatchFieldAllowed("ext.x"));

        // `ext.` itself names the namespace, not a claim — admitting it would let a reactor
        // set a claim literally called `ext.`.
        Assert.False(spec.PatchFieldAllowed("ext."));
        Assert.False(spec.PatchFieldAllowed("ext"));
        Assert.False(spec.PatchFieldAllowed("extra"));
        Assert.False(spec.PatchFieldAllowed("external_id"));
        Assert.False(spec.PatchFieldAllowed("evil.ext.department"));
        Assert.False(spec.PatchFieldAllowed(null));
    }

    [Fact]
    public void NoStandardClaim_IsReachableFromTokenPreIssue()
    {
        ReactorEventSpec spec = ReactorEvents.Spec(ReactorEvents.TokenPreIssue)!;
        foreach (string claim in new[]
                 {
                     "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "scope", "scp", "azp", "act",
                     "client_id",
                 })
        {
            Assert.False(
                spec.PatchFieldAllowed(claim),
                $"a hook that can rewrite `{claim}` is a hook that can mint a token for anyone");
        }
    }

    [Theory]
    [InlineData(ReactorEvents.UserPreCreate)]
    [InlineData(ReactorEvents.UserPreUpdate)]
    public void UserEvents_AdmitProfileFieldsAndRefuseCredentialsAndBareMetadata(string name)
    {
        ReactorEventSpec spec = ReactorEvents.Spec(name)!;

        Assert.True(spec.PatchFieldAllowed("username"));
        Assert.True(spec.PatchFieldAllowed("email"));
        Assert.True(spec.PatchFieldAllowed("metadata.source"));

        Assert.False(spec.PatchFieldAllowed("metadata"), "bare `metadata` is refused by the prefix rule");
        Assert.False(spec.PatchFieldAllowed("metadata."));
        Assert.False(spec.PatchFieldAllowed("password"));
        Assert.False(spec.PatchFieldAllowed("password_hash"));
        Assert.False(spec.PatchFieldAllowed("tenant_id"));
        Assert.False(spec.PatchFieldAllowed("id"));
        Assert.False(spec.PatchFieldAllowed("roles"));
        Assert.False(spec.PatchFieldAllowed("is_admin"));
    }

    [Theory]
    [InlineData(ReactorEvents.LoginPostAuth)]
    [InlineData(ReactorEvents.GrantPreAssign)]
    public void VetoOnlyEvents_AcceptNoPatchFieldAtAll(string name)
    {
        ReactorEventSpec spec = ReactorEvents.Spec(name)!;

        Assert.False(spec.Mutable);
        Assert.Empty(spec.MutableFields);
        foreach (string field in new[] { "ext.department", "username", "email", "anything" })
        {
            Assert.False(spec.PatchFieldAllowed(field));
        }
    }

    [Fact]
    public void TheRegistry_MatchesTheServersFiveEntries()
    {
        Assert.Equal(5, ReactorEvents.Registry.Count);
        Assert.Equal(
            new[]
            {
                ReactorEvents.TokenPreIssue, ReactorEvents.LoginPostAuth, ReactorEvents.UserPreCreate,
                ReactorEvents.UserPreUpdate, ReactorEvents.GrantPreAssign,
            },
            ReactorEvents.Registry.Select(spec => spec.Name).ToArray());

        // All five v1 events are interceptable; the flag exists because the registry carries
        // it and a sixth event may not be.
        Assert.All(ReactorEvents.Registry, spec => Assert.True(spec.Interceptable));
        Assert.All(ReactorEvents.Registry, spec => Assert.False(string.IsNullOrWhiteSpace(spec.Description)));

        Assert.Null(ReactorEvents.Spec(null));
        Assert.Null(ReactorEvents.Spec("no.such.event"));
    }

    // ---- §22.7 hot-path exclusion (MUST NOT) -------------------------------

    /// <summary>
    /// &#167;22.7 is written as a MUST NOT: <c>authz.check</c>, <c>authz.check_batch</c> and
    /// <c>token.introspect</c> are not hookable and no SDK may present them as such. Asserted
    /// against the registry AND against every public string constant this namespace exposes —
    /// on the list, not on a comment.
    /// </summary>
    [Fact]
    public void TheHotPathOperations_AreAbsentFromEveryEventConstant()
    {
        string[] excluded = { "authz.check", "authz.check_batch", "token.introspect" };

        foreach (string name in excluded)
        {
            Assert.Null(ReactorEvents.Spec(name));
            Assert.DoesNotContain(ReactorEvents.Registry, spec => spec.Name == name);
        }

        List<string> constants = typeof(ReactorEvents)
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(f => f is { IsLiteral: true, IsInitOnly: false } && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToList();

        Assert.Equal(5, constants.Count);
        foreach (string name in excluded)
        {
            Assert.DoesNotContain(name, constants);
        }

        // And there is no reactor-shaped interceptor offered for them anywhere in the
        // namespace either — no type whose name suggests one.
        IEnumerable<string> reactorTypes = typeof(ReactorEvents).Assembly
            .GetExportedTypes()
            .Where(t => t.Namespace == "Axiam.Sdk.Reactor")
            .Select(t => t.Name.ToLowerInvariant());
        Assert.DoesNotContain(reactorTypes, n => n.Contains("check", StringComparison.Ordinal)
            || n.Contains("introspect", StringComparison.Ordinal));
    }

    // ---- §22.8 failure-policy composition ----------------------------------

    /// <summary>
    /// &#167;22.8: a registration naming no <c>failure_policy</c> inherits the strictest
    /// default among its events — <b>in either array order</b>. "Take the first event's
    /// default" would let the order of a JSON array decide whether an unreachable fraud check
    /// passes.
    /// </summary>
    [Fact]
    public void TheStrictestDefault_WinsInEitherArrayOrder()
    {
        Assert.Equal(
            FailurePolicy.FailClosed,
            ReactorEvents.DefaultFailurePolicyFor(new[] { ReactorEvents.TokenPreIssue, ReactorEvents.LoginPostAuth }));
        Assert.Equal(
            FailurePolicy.FailClosed,
            ReactorEvents.DefaultFailurePolicyFor(new[] { ReactorEvents.LoginPostAuth, ReactorEvents.TokenPreIssue }));

        Assert.Equal(
            FailurePolicy.FailOpen,
            ReactorEvents.DefaultFailurePolicyFor(new[] { ReactorEvents.TokenPreIssue }));
        Assert.Equal(FailurePolicy.FailOpen, ReactorEvents.DefaultFailurePolicyFor(Array.Empty<string>()));

        // An event the server would refuse at registration must not be guessed a policy for.
        Assert.Equal(FailurePolicy.FailOpen, ReactorEvents.DefaultFailurePolicyFor(new[] { "authz.check" }));
        Assert.Throws<ArgumentNullException>(() => ReactorEvents.DefaultFailurePolicyFor(null!));
    }

    [Fact]
    public void TheRegistrysPerEventDefaults_MatchTheServers()
    {
        Assert.Equal(FailurePolicy.FailOpen, ReactorEvents.Spec(ReactorEvents.TokenPreIssue)!.DefaultFailurePolicy);
        Assert.Equal(FailurePolicy.FailClosed, ReactorEvents.Spec(ReactorEvents.LoginPostAuth)!.DefaultFailurePolicy);
        Assert.Equal(FailurePolicy.FailClosed, ReactorEvents.Spec(ReactorEvents.UserPreCreate)!.DefaultFailurePolicy);
        Assert.Equal(FailurePolicy.FailClosed, ReactorEvents.Spec(ReactorEvents.UserPreUpdate)!.DefaultFailurePolicy);
        Assert.Equal(FailurePolicy.FailClosed, ReactorEvents.Spec(ReactorEvents.GrantPreAssign)!.DefaultFailurePolicy);
    }

    [Fact]
    public void FailurePolicyWireForms_RoundTrip()
    {
        Assert.Equal("fail_open", FailurePolicy.FailOpen.ToWire());
        Assert.Equal("fail_closed", FailurePolicy.FailClosed.ToWire());

        Assert.Equal(FailurePolicy.FailOpen, FailurePolicyExtensions.FromWire("fail_open"));
        Assert.Equal(FailurePolicy.FailClosed, FailurePolicyExtensions.FromWire("  FAIL_CLOSED  "));
        Assert.Null(FailurePolicyExtensions.FromWire(null));
        Assert.Null(FailurePolicyExtensions.FromWire(""));
        Assert.Null(FailurePolicyExtensions.FromWire("fail_sideways"));
    }

    // ---- §22.8 budget constants --------------------------------------------

    [Fact]
    public void TheBudgetConstants_AreTheContractsOwn()
    {
        Assert.Equal(500, ReactorProtocol.DefaultTimeoutMs);
        Assert.Equal(5_000, ReactorProtocol.MaxTimeoutMs);
        Assert.Equal(5_000, ReactorProtocol.ChainCeilingMs);
        Assert.Equal(64, ReactorProtocol.DefaultMaxInFlightPerTenant);
        Assert.Equal(2, ReactorProtocol.KeyVersion);
        Assert.Equal(2, ReactorProtocol.MinAcceptedKeyVersion);
        Assert.Equal(TimeSpan.FromSeconds(300), ReactorProtocol.DefaultFreshnessSkew);
        Assert.Equal("axiam.reactor.events", ReactorProtocol.Exchange);
    }

    // ---- §22.4, encoded in the type system ---------------------------------

    [Fact]
    public void TheDecisionTypes_EncodeThreeSection224RulesStructurally()
    {
        // 1. allow cannot carry a patch — there is no constructor that would take one.
        var allow = Assert.IsType<ReactorDecision.Allow>(ReactorDecision.Allowed());
        Assert.False(allow.RequireMfa);
        Assert.Equal("allow", allow.Wire);
        Assert.DoesNotContain(typeof(ReactorDecision.Allow).GetProperties(), p => p.Name == "Patch");

        // 2. an empty mutation is unrepresentable rather than merely discouraged.
        Assert.Throws<ArgumentException>(() =>
            ReactorDecision.Mutated(new Dictionary<string, string>()));
        Assert.Throws<ArgumentNullException>(() => ReactorDecision.Mutated(null!));

        // 3. require_mfa rides on allow — it is a flag, not a fourth decision.
        var stepUp = Assert.IsType<ReactorDecision.Allow>(ReactorDecision.AllowRequiringStepUp());
        Assert.True(stepUp.RequireMfa);
        Assert.Equal("allow", stepUp.Wire);

        var deny = Assert.IsType<ReactorDecision.Deny>(ReactorDecision.Denied("nope"));
        Assert.Equal("nope", deny.Reason);
        Assert.Equal("deny", deny.Wire);
        Assert.Null(Assert.IsType<ReactorDecision.Deny>(ReactorDecision.Denied()).Reason);

        var mutate = Assert.IsType<ReactorDecision.Mutate>(
            ReactorDecision.Mutated(new Dictionary<string, string> { ["ext.a"] = "1" }));
        Assert.Equal("mutate", mutate.Wire);
        Assert.Equal("1", mutate.Patch["ext.a"]);

        // The hierarchy is closed: only this assembly can add a subclass, because the base
        // constructor is private protected.
        Type[] subclasses = typeof(ReactorDecision).Assembly.GetTypes()
            .Where(t => t.IsSubclassOf(typeof(ReactorDecision))).ToArray();
        Assert.Equal(3, subclasses.Length);
    }
}
