using System.Net;
using System.Net.Http;
using Axiam.Sdk.Amqp;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Options;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Focused coverage for the SDK's small value/record/exception types and the remaining
/// <see cref="NetworkError"/> redaction branches (safe-header preservation +
/// <c>SanitizeMessage</c>), which the transport-level suites do not otherwise reach.
/// </summary>
[Trait("Category", "Fast")]
public class CoreValueTypesTests
{
    [Fact]
    public void TokenPair_ExposesWrappedValues_Redacted_AndKeepsExpiry()
    {
        DateTimeOffset expiry = DateTimeOffset.UtcNow.AddMinutes(15);
        var pair = new TokenPair(Sensitive.Of("access"), Sensitive.Of("refresh"), expiry);

        Assert.Equal("access", pair.AccessToken.Reveal());
        Assert.Equal("refresh", pair.RefreshToken.Reveal());
        Assert.Equal(expiry, pair.ExpiresAt);
        // The record's ToString must never surface a wrapped token value.
        Assert.DoesNotContain("access", pair.ToString());
        Assert.Contains("[SENSITIVE]", pair.ToString());
    }

    [Fact]
    public void LoginResult_MfaChallenge_CarriesChallengeToken()
    {
        var result = new LoginResult(true, Sensitive.Of("chal"));
        Assert.True(result.MfaRequired);
        Assert.Equal("chal", result.ChallengeToken!.Value.Reveal());

        var noMfa = new LoginResult(false);
        Assert.False(noMfa.MfaRequired);
        Assert.Null(noMfa.ChallengeToken);
    }

    [Fact]
    public void PoisonMessageException_AllThreeConstructors()
    {
        var empty = new PoisonMessageException();
        Assert.NotNull(empty.Message);

        var withMessage = new PoisonMessageException("bad payload");
        Assert.Equal("bad payload", withMessage.Message);

        var cause = new InvalidOperationException("root");
        var wrapped = new PoisonMessageException("bad payload", cause);
        Assert.Equal("bad payload", wrapped.Message);
        Assert.Same(cause, wrapped.InnerException);
    }

    [Fact]
    public void AuthzError_MessageOnlyConstructor_LeavesActionAndResourceNull()
    {
        var error = new AuthzError("denied");
        Assert.Equal("denied", error.Message);
        Assert.Null(error.Action);
        Assert.Null(error.ResourceId);
    }

    [Fact]
    public void AxiamClientOptions_HasContractDefaults()
    {
        var options = new AxiamClientOptions { BaseUrl = new Uri("https://axiam.test"), TenantId = "t" };

        Assert.Equal(TimeSpan.FromMinutes(5), options.JwksCacheTtl);
        Assert.Equal(TimeSpan.FromSeconds(10), options.ConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(30), options.RequestTimeout);
        Assert.Equal(3, options.MaxRetryAttempts);
        Assert.Equal(TimeSpan.FromMilliseconds(200), options.RetryBaseDelay);
        Assert.Equal(TimeSpan.FromSeconds(5), options.RetryMaxDelay);
    }

    [Fact]
    public void TenantContext_CarriesOrgIdAndSlug()
    {
        Guid org = Guid.NewGuid();
        var withId = new TenantContext("acme", org);
        Assert.Equal("acme", withId.TenantId);
        Assert.Equal(org, withId.OrgId);
        Assert.Null(withId.OrgSlug);

        var withSlug = new TenantContext("acme", orgId: null, orgSlug: "acme-org");
        Assert.Equal("acme-org", withSlug.OrgSlug);
        Assert.Null(withSlug.OrgId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void TenantContext_BlankTenant_Throws(string? blank)
    {
        Assert.Throws<ArgumentException>(() => new TenantContext(blank!));
    }

    [Fact]
    public void NetworkError_FromResponse_PreservesSafeHeaderValue_RedactsUnsafeOne()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.BadGateway);
        response.Headers.TryAddWithoutValidation("X-Request-Id", "trace-123"); // allowlisted -> value kept
        response.Headers.TryAddWithoutValidation("X-Auth-Token", "secret-value"); // not allowlisted -> redacted

        NetworkError error = NetworkError.FromResponse(response, "bad gateway");

        Assert.Contains("trace-123", error.Message);
        Assert.Contains("X-Auth-Token: [REDACTED]", error.Message);
        Assert.DoesNotContain("secret-value", error.Message);
    }

    [Fact]
    public void NetworkError_SanitizeMessage_StripsSensitiveHeaderFragments()
    {
        string sanitized = NetworkError.SanitizeMessage("failure Authorization: Bearer abc123 while connecting");
        Assert.DoesNotContain("abc123", sanitized);
        Assert.Contains("[SENSITIVE]", sanitized);
    }

    [Fact]
    public void NetworkError_FromException_NullException_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => NetworkError.FromException(null!, "ctx"));
    }
}
