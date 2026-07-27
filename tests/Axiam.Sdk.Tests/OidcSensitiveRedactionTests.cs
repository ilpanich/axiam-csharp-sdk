using System.Text.Json;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;12.5: <c>access_token</c>, <c>refresh_token</c>, <c>id_token</c>,
/// <c>client_secret</c>, and <c>code_verifier</c> MUST NOT appear in
/// <see cref="object.ToString"/> or JSON serialization output for any of the new &#167;12
/// types that carry them.
/// </summary>
[Trait("Category", "Fast")]
public class OidcSensitiveRedactionTests
{
    private const string SecretMarker = "totally-secret-value-should-never-leak";

    [Fact]
    public void OidcTokenSet_ToString_RedactsAllThreeTokenFields()
    {
        var tokenSet = new OidcTokenSet(
            Sensitive.Of("access-" + SecretMarker),
            "Bearer",
            900,
            "openid",
            Sensitive.Of("refresh-" + SecretMarker),
            Sensitive.Of("idtok-" + SecretMarker),
            IdClaims: null);

        string rendered = tokenSet.ToString();

        Assert.DoesNotContain(SecretMarker, rendered);
        Assert.Contains("[SENSITIVE]", rendered);
    }

    [Fact]
    public void OidcTokenSet_JsonSerialize_RedactsAllThreeTokenFields()
    {
        var tokenSet = new OidcTokenSet(
            Sensitive.Of("access-" + SecretMarker),
            "Bearer",
            900,
            "openid",
            Sensitive.Of("refresh-" + SecretMarker),
            Sensitive.Of("idtok-" + SecretMarker),
            IdClaims: null);

        string json = JsonSerializer.Serialize(tokenSet);

        Assert.DoesNotContain(SecretMarker, json);
    }

    [Fact]
    public void AuthorizationRequest_ToString_RedactsCodeVerifier()
    {
        var request = new AuthorizationRequest("https://idp/authorize?x=1", "state-1", "nonce-1", Sensitive.Of(SecretMarker));

        string rendered = request.ToString();

        Assert.DoesNotContain(SecretMarker, rendered);
        // state/nonce are NOT secrets (§12.3 rule 2) — they legitimately appear.
        Assert.Contains("state-1", rendered);
        Assert.Contains("nonce-1", rendered);
    }

    [Fact]
    public void AuthorizationRequest_JsonSerialize_RedactsCodeVerifier()
    {
        var request = new AuthorizationRequest("https://idp/authorize?x=1", "state-1", "nonce-1", Sensitive.Of(SecretMarker));

        string json = JsonSerializer.Serialize(request);

        Assert.DoesNotContain(SecretMarker, json);
    }

    [Fact]
    public void Sensitive_Expose_ReturnsRawValue_ButToStringStaysRedacted()
    {
        // The documented §7-vs-§12 accessor: Expose() is the ONLY way to read the raw
        // value back out, and using it never weakens the ToString()/JSON redaction.
        Sensitive<string> wrapped = Sensitive<string>.Wrap(SecretMarker);

        Assert.Equal(SecretMarker, wrapped.Expose());
        Assert.Equal("[SENSITIVE]", wrapped.ToString());
        Assert.DoesNotContain(SecretMarker, JsonSerializer.Serialize(wrapped));
    }
}
