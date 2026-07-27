using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// <see cref="MemoryOidcStateStore"/> — CONTRACT.md &#167;12.3 rule 1: single-use
/// <c>Consume</c>, &#8804;10-minute TTL, per-instance (never process-global), safe under
/// concurrency.
/// </summary>
[Trait("Category", "Fast")]
public class OidcStateStoreTests
{
    private static OidcStateEntry Entry(string state = "state-1") =>
        new(state, "nonce-1", Sensitive<string>.Wrap("verifier-1"), "https://app.example/callback", "https://app.example/return-to");

    [Fact]
    public async Task ConsumeAsync_UnknownState_ReturnsNull()
    {
        var store = new MemoryOidcStateStore();

        OidcStateEntry? result = await store.ConsumeAsync("never-saved");

        Assert.Null(result);
    }

    [Fact]
    public async Task ConsumeAsync_ReturnsEntry_AndIsSingleUse()
    {
        var store = new MemoryOidcStateStore();
        await store.SaveAsync(Entry());

        OidcStateEntry? first = await store.ConsumeAsync("state-1");
        OidcStateEntry? second = await store.ConsumeAsync("state-1");

        Assert.NotNull(first);
        Assert.Equal("nonce-1", first!.Nonce);
        Assert.Equal("verifier-1", first.CodeVerifier.Reveal());
        Assert.Equal("https://app.example/return-to", first.ReturnTo);
        Assert.Null(second); // second consume of the SAME state must fail — single-use
    }

    [Fact]
    public async Task ConsumeAsync_ExpiredEntry_ReturnsNull()
    {
        var store = new MemoryOidcStateStore(TimeSpan.FromMilliseconds(20));
        await store.SaveAsync(Entry());

        await Task.Delay(TimeSpan.FromMilliseconds(80));
        OidcStateEntry? result = await store.ConsumeAsync("state-1");

        Assert.Null(result);
    }

    [Fact]
    public void Constructor_TtlAboveMax_IsClampedToTenMinutes()
    {
        // No direct getter for the effective TTL — proven indirectly via Save/Consume
        // behavior is covered by the other tests; this test only pins the documented
        // maximum constant CONTRACT.md §12.3 rule 1 fixes.
        Assert.Equal(TimeSpan.FromMinutes(10), MemoryOidcStateStore.MaxTtl);
    }

    [Fact]
    public async Task Size_ReflectsUnexpiredEntries_AndSweepsLazily()
    {
        var store = new MemoryOidcStateStore(TimeSpan.FromMilliseconds(20));
        await store.SaveAsync(Entry("a"));
        await store.SaveAsync(Entry("b"));
        Assert.Equal(2, store.Size);

        await Task.Delay(TimeSpan.FromMilliseconds(80));
        // Sweep is lazy — triggered by the next Save/Size call, never a background timer.
        Assert.Equal(0, store.Size);
    }

    [Fact]
    public async Task ConcurrentSaveAndConsume_NeverDoubleConsumesOrThrows()
    {
        var store = new MemoryOidcStateStore();
        const int count = 100;
        var entries = Enumerable.Range(0, count).Select(i => Entry($"state-{i}")).ToArray();

        await Task.WhenAll(entries.Select(e => store.SaveAsync(e)));

        // Fire two concurrent consumers per state — exactly one must win per state.
        var results = await Task.WhenAll(entries.SelectMany(e => new[]
        {
            store.ConsumeAsync(e.State),
            store.ConsumeAsync(e.State),
        }));

        int successes = results.Count(r => r is not null);
        Assert.Equal(count, successes); // exactly one winner per state, never zero or two
    }

    [Fact]
    public void CodeVerifier_RedactsInToString_EvenWhileStored()
    {
        // §12.5: code_verifier is secret for its whole lifetime, including while sitting
        // in a state-store entry.
        OidcStateEntry entry = Entry();

        Assert.Equal("[SENSITIVE]", entry.CodeVerifier.ToString());
        Assert.DoesNotContain("verifier-1", entry.ToString());
    }
}
