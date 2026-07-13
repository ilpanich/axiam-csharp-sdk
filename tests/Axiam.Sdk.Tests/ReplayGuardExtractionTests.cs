using System.Text;
using Axiam.Sdk.Amqp;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Direct coverage for <see cref="ReplayGuard.TryExtractMetadata"/>'s parse/failure
/// branches and the public constructor's default-skew fallback — the parts of NEW-4 the
/// consumer/ack-matrix and reference-vector suites do not exercise in isolation.
/// </summary>
[Trait("Category", "Fast")]
public class ReplayGuardExtractionTests
{
    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    [Fact]
    public void TryExtractMetadata_MissingKeyVersion_YieldsZero()
    {
        bool ok = ReplayGuard.TryExtractMetadata(
            Utf8("""{"nonce":"n1","issued_at":"2026-07-10T12:00:00Z"}"""), out ReplayMetadata meta);

        Assert.True(ok);
        Assert.Equal(0, meta.KeyVersion);
        Assert.Equal("n1", meta.Nonce);
    }

    [Fact]
    public void TryExtractMetadata_MissingNonce_ReturnsFalse()
    {
        bool ok = ReplayGuard.TryExtractMetadata(
            Utf8("""{"key_version":2,"issued_at":"2026-07-10T12:00:00Z"}"""), out _);

        Assert.False(ok);
    }

    [Fact]
    public void TryExtractMetadata_MissingIssuedAt_ReturnsFalse()
    {
        bool ok = ReplayGuard.TryExtractMetadata(
            Utf8("""{"key_version":2,"nonce":"n1"}"""), out _);

        Assert.False(ok);
    }

    [Fact]
    public void TryExtractMetadata_NonObjectJson_ReturnsFalse()
    {
        Assert.False(ReplayGuard.TryExtractMetadata(Utf8("[1,2,3]"), out _));
    }

    [Fact]
    public void TryExtractMetadata_MalformedJson_ReturnsFalse()
    {
        Assert.False(ReplayGuard.TryExtractMetadata(Utf8("{not json"), out _));
    }

    [Fact]
    public void TryExtractMetadata_WrongTypeForNonce_ReturnsFalse()
    {
        // nonce as a number, not a string -> GetValue<string>() throws internally -> false.
        Assert.False(ReplayGuard.TryExtractMetadata(
            Utf8("""{"key_version":2,"nonce":123,"issued_at":"2026-07-10T12:00:00Z"}"""), out _));
    }

    [Fact]
    public void PublicConstructor_NullSkew_UsesDefaultSkew()
    {
        var guard = new ReplayGuard(null);
        Assert.Equal(ReplayGuard.DefaultSkew, guard.Skew);
    }

    [Fact]
    public void PublicConstructor_NonPositiveSkew_UsesDefaultSkew()
    {
        var guard = new ReplayGuard(TimeSpan.FromSeconds(-1));
        Assert.Equal(ReplayGuard.DefaultSkew, guard.Skew);
    }

    [Fact]
    public void PublicConstructor_PositiveSkew_IsHonored()
    {
        var skew = TimeSpan.FromMinutes(2);
        var guard = new ReplayGuard(skew);
        Assert.Equal(skew, guard.Skew);
    }
}
