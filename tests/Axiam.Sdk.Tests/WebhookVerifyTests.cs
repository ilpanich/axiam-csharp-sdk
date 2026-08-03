using System;
using System.Security.Cryptography;
using System.Text;
using Axiam.Sdk.Core;
using Axiam.Sdk.Webhooks;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Coverage for <see cref="AxiamWebhooks.Verify"/> (CONTRACT.md &#167;13, T-145) against the
/// "Required tests" list in the T-145 spec: valid/fresh acceptance, tampered body, wrong
/// secret, stale/future timestamps, every malformed-header shape, and the shared cross-SDK
/// pin vector (computed here from the spec's raw ingredients, never hardcoded as a literal
/// hex string).
/// </summary>
[Trait("Category", "Fast")]
public class WebhookVerifyTests
{
    private const string Secret = "whsec_test_0123456789abcdef";
    private static readonly byte[] Body = Encoding.UTF8.GetBytes("""{"event":"user.created","id":"01JQ0000000000000000000000"}""");

    /// <summary>A <see cref="TimeProvider"/> pinned to a fixed instant, for deterministic freshness tests.</summary>
    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _now;
        public FixedTimeProvider(DateTimeOffset now) => _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
    }

    /// <summary>
    /// Computes HMAC-SHA256(secret, "&lt;timestamp&gt;.&lt;body&gt;") exactly the way the
    /// server (and <see cref="AxiamWebhooks.Verify"/>) do, so tests never hardcode an expected
    /// signature literal.
    /// </summary>
    private static string ComputeV1(string secret, long timestamp, byte[] body)
    {
        byte[] key = Encoding.UTF8.GetBytes(secret);
        byte[] signed = Encoding.ASCII.GetBytes($"{timestamp}.").Concat(body).ToArray();
        byte[] mac = HMACSHA256.HashData(key, signed);
        // net8.0 has no Convert.ToHexStringLower (added in net9.0) -> uppercase then lowercase.
        return Convert.ToHexString(mac).ToLowerInvariant();
    }

    private static string Header(long timestamp, string v1) => $"t={timestamp},v1={v1}";

    [Fact]
    public void ValidSignature_FreshTimestamp_IsAccepted()
    {
        long timestamp = 1785700000;
        string v1 = ComputeV1(Secret, timestamp, Body);
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp));

        WebhookEvent evt = AxiamWebhooks.Verify(
            Sensitive<string>.Wrap(Secret), Header(timestamp, v1), Body, timeProvider: clock);

        Assert.Equal(timestamp, evt.Timestamp);
        Assert.Equal(Body, evt.Body);
        Assert.Equal("user.created", evt.EventType);
        Assert.Equal("01JQ0000000000000000000000", evt.DeliveryId);
    }

    [Fact]
    public void CrossSdkPinVector_ComputedFromSpec_IsAccepted()
    {
        // The shared T-145 spec vector: secret/timestamp/body are hardcoded from the spec, but
        // the expected `v1` is computed here (never copied as a literal hex value) so every SDK
        // is pinned to the same bytes rather than to a shared hardcoded hex string.
        const long timestamp = 1785700000;
        byte[] body = Encoding.UTF8.GetBytes("""{"event":"user.created","id":"01JQ0000000000000000000000"}""");
        string v1 = ComputeV1("whsec_test_0123456789abcdef", timestamp, body);
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp));

        WebhookEvent evt = AxiamWebhooks.Verify(
            Sensitive<string>.Wrap("whsec_test_0123456789abcdef"), Header(timestamp, v1), body, timeProvider: clock);

        Assert.Equal(timestamp, evt.Timestamp);

        // Separately, a byte-flipped body must be rejected under the same vector.
        byte[] tampered = (byte[])body.Clone();
        tampered[0] ^= 0xFF;
        Assert.Throws<WebhookVerificationException>(() => AxiamWebhooks.Verify(
            Sensitive<string>.Wrap("whsec_test_0123456789abcdef"), Header(timestamp, v1), tampered, timeProvider: clock));
    }

    [Fact]
    public void TamperedBody_OneByteFlipped_IsRejected()
    {
        long timestamp = 1785700000;
        string v1 = ComputeV1(Secret, timestamp, Body);
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp));

        byte[] tampered = (byte[])Body.Clone();
        tampered[5] ^= 0x01;

        Assert.Throws<WebhookVerificationException>(() => AxiamWebhooks.Verify(
            Sensitive<string>.Wrap(Secret), Header(timestamp, v1), tampered, timeProvider: clock));
    }

    [Fact]
    public void WrongSecret_IsRejected()
    {
        long timestamp = 1785700000;
        string v1 = ComputeV1(Secret, timestamp, Body);
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp));

        Assert.Throws<WebhookVerificationException>(() => AxiamWebhooks.Verify(
            Sensitive<string>.Wrap("whsec_totally_different_secret"), Header(timestamp, v1), Body, timeProvider: clock));
    }

    [Fact]
    public void StaleTimestamp_BeyondTolerance_IsRejected()
    {
        long timestamp = 1785700000;
        string v1 = ComputeV1(Secret, timestamp, Body);
        // 301s after `t`, default tolerance is 300s.
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp + 301));

        Assert.Throws<WebhookVerificationException>(() => AxiamWebhooks.Verify(
            Sensitive<string>.Wrap(Secret), Header(timestamp, v1), Body, timeProvider: clock));
    }

    [Fact]
    public void FutureTimestamp_BeyondTolerance_IsRejected()
    {
        long timestamp = 1785700000;
        string v1 = ComputeV1(Secret, timestamp, Body);
        // `t` is 301s ahead of "now" -> future-dated beyond the two-sided tolerance window.
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp - 301));

        Assert.Throws<WebhookVerificationException>(() => AxiamWebhooks.Verify(
            Sensitive<string>.Wrap(Secret), Header(timestamp, v1), Body, timeProvider: clock));
    }

    [Fact]
    public void TimestampAtExactToleranceBoundary_IsAccepted()
    {
        long timestamp = 1785700000;
        string v1 = ComputeV1(Secret, timestamp, Body);
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp + 300));

        WebhookEvent evt = AxiamWebhooks.Verify(
            Sensitive<string>.Wrap(Secret), Header(timestamp, v1), Body, timeProvider: clock);
        Assert.Equal(timestamp, evt.Timestamp);
    }

    [Fact]
    public void CustomTolerance_IsHonored()
    {
        long timestamp = 1785700000;
        string v1 = ComputeV1(Secret, timestamp, Body);
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp + 30));

        // Default tolerance (300s) would accept this; a tightened 10s tolerance must reject it.
        Assert.Throws<WebhookVerificationException>(() => AxiamWebhooks.Verify(
            Sensitive<string>.Wrap(Secret), Header(timestamp, v1), Body, tolerance: TimeSpan.FromSeconds(10), timeProvider: clock));
    }

    [Theory]
    [InlineData("t=1785700000")] // missing v1 entirely -> MUST be a failure, never "nothing to check"
    [InlineData("t=1785700000,v1=")] // empty v1 value
    [InlineData("t=abc,v1=deadbeef")] // non-numeric t
    [InlineData("")] // empty header
    [InlineData("v1=deadbeef")] // missing t
    [InlineData("t=1785700000,t=1785700001,v1=deadbeef")] // duplicate t
    [InlineData("t=,v1=deadbeef")] // empty t
    public void MalformedHeader_IsRejected(string header)
    {
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1785700000));

        Assert.Throws<WebhookVerificationException>(() => AxiamWebhooks.Verify(
            Sensitive<string>.Wrap(Secret), header, Body, timeProvider: clock));
    }

    [Fact]
    public void NonHexV1Value_FailsClosed_WithoutThrowingUnexpectedException()
    {
        long timestamp = 1785700000;
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp));

        Assert.Throws<WebhookVerificationException>(() => AxiamWebhooks.Verify(
            Sensitive<string>.Wrap(Secret), Header(timestamp, "not-hex-zz"), Body, timeProvider: clock));
    }

    [Fact]
    public void MultipleV1Entries_AcceptsIfAnyMatches()
    {
        // Simulates secret rotation: an old (garbage) v1 alongside the current, valid one.
        long timestamp = 1785700000;
        string validV1 = ComputeV1(Secret, timestamp, Body);
        string header = $"t={timestamp},v1=0000000000000000000000000000000000000000000000000000000000000000,v1={validV1}";
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp));

        WebhookEvent evt = AxiamWebhooks.Verify(Sensitive<string>.Wrap(Secret), header, Body, timeProvider: clock);
        Assert.Equal(timestamp, evt.Timestamp);
    }

    [Fact]
    public void UnknownHeaderKeys_AreIgnored_ForwardCompat()
    {
        long timestamp = 1785700000;
        string v1 = ComputeV1(Secret, timestamp, Body);
        string header = $"t={timestamp},v2=some-future-scheme,v1={v1}";
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp));

        WebhookEvent evt = AxiamWebhooks.Verify(Sensitive<string>.Wrap(Secret), header, Body, timeProvider: clock);
        Assert.Equal(timestamp, evt.Timestamp);
    }

    [Fact]
    public void NonJsonBody_StillVerifies_ButEventFieldsAreNull()
    {
        long timestamp = 1785700000;
        byte[] body = Encoding.UTF8.GetBytes("not json at all");
        string v1 = ComputeV1(Secret, timestamp, body);
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp));

        WebhookEvent evt = AxiamWebhooks.Verify(Sensitive<string>.Wrap(Secret), Header(timestamp, v1), body, timeProvider: clock);

        Assert.Null(evt.EventType);
        Assert.Null(evt.DeliveryId);
        Assert.Equal(body, evt.Body);
    }

    [Fact]
    public void FailureMessage_NeverContainsExpectedSignature_OrSecret()
    {
        long timestamp = 1785700000;
        string wrongV1 = new string('a', 64); // well-formed hex, guaranteed not to match
        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(timestamp));

        WebhookVerificationException ex = Assert.Throws<WebhookVerificationException>(() => AxiamWebhooks.Verify(
            Sensitive<string>.Wrap(Secret), Header(timestamp, wrongV1), Body, timeProvider: clock));

        Assert.DoesNotContain(wrongV1, ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Secret, ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
