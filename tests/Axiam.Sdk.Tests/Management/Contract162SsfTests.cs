using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Ssf;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// CONTRACT.md contract 1.62, &#167;32.2 and &#167;32.8 test 7: the change-taking form of an SSF stream, the
/// response's own <c>updated_at</c> string as <c>expected_updated_at</c> (item (g)), an assigned
/// <c>null</c> as "none" (item (f)), and the three meanings of <c>events_requested</c> stated at the
/// <c>update_stream</c> call site (item (h)).
/// </summary>
[Trait("Category", "Fast")]
public sealed class Contract162SsfTests : ManagementTestBase
{
    // ------------------------------------------------------------------
    // §32.8 test 7 — the change-taking form of a stream
    // ------------------------------------------------------------------

    private static JsonObject StreamBody(string updatedAt, JsonArray requested) => new()
    {
        ["id"] = Guid.NewGuid().ToString(),
        ["tenant_id"] = TenantId.ToString(),
        ["receiver_client_id"] = "rp-client",
        ["audience"] = "https://rp.example",
        ["description"] = "orig",
        ["delivery_method"] = "push",
        ["endpoint_url"] = "https://rp.example/ssf/push",
        ["authorization_header_set"] = true,
        ["events_allowed"] = new JsonArray(SsfEventTypes.SessionRevoked, SsfEventTypes.AccountDisabled, SsfEventTypes.AccountEnabled),
        ["events_requested"] = requested,
        ["events_delivered"] = new JsonArray(),
        ["subject_format"] = "iss_sub",
        ["status"] = "enabled",
        ["status_reason"] = null,
        ["status_actor"] = "admin",
        ["last_verification_at"] = null,
        ["created_at"] = "2026-10-04T00:00:00Z",
        ["updated_at"] = updatedAt,
        ["transmitter_active"] = true,
    };

    private async Task<SsfStream> ReadStream(string updatedAt, JsonArray requested)
    {
        Guid id = Guid.NewGuid();
        Mount("GET", $"/api/v1/tenants/{TenantId}/ssf/streams/{id}", 200, StreamBody(updatedAt, requested).ToJsonString());
        return await Client.Ssf.GetStreamAsync(id);
    }

    /// <summary>Lowering the ceiling cuts <c>events_requested</c> to it; nothing about events sends it as read, <c>[]</c> as <c>[]</c>.</summary>
    [Fact]
    public async Task TheChangeTakingFormCutsRequestedToTheNewCeilingAndSendsTheRestAsRead()
    {
        // A fixture whose updated_at carries a +00:00 offset and nine fraction digits.
        const string version = "2026-10-05T01:02:03.123456789+00:00";
        SsfStream stream = await ReadStream(version, new JsonArray(SsfEventTypes.SessionRevoked, SsfEventTypes.AccountDisabled));

        SsfStreamInput lowered = stream.ToInput(new SsfStreamChanges { EventsAllowed = new[] { SsfEventType.AccountDisabled } });
        Assert.Equal(new[] { SsfEventType.AccountDisabled }, lowered.EventsAllowed);
        Assert.Equal(new[] { SsfEventType.AccountDisabled }, lowered.EventsRequested);   // only what is in the new ceiling
        Assert.Equal(version, lowered.ExpectedUpdatedAt);
        Assert.Null(lowered.AuthorizationHeader);                                         // absent keeps the stored header
        Assert.Null(lowered.ClearAuthorizationHeader);

        // The order of the entries that stay is the read order.
        SsfStreamInput widerCeiling = stream.ToInput(new SsfStreamChanges
        {
            EventsAllowed = new[] { SsfEventType.AccountDisabled, SsfEventType.SessionRevoked },
        });
        Assert.Equal(new[] { SsfEventType.SessionRevoked, SsfEventType.AccountDisabled }, widerCeiling.EventsRequested);

        // A change that says nothing about events sends events_requested as read.
        SsfStreamInput renamed = stream.ToInput(new SsfStreamChanges { Description = "renamed" });
        Assert.Equal("renamed", renamed.Description);
        Assert.Equal(new[] { SsfEventType.SessionRevoked, SsfEventType.AccountDisabled }, renamed.EventsRequested);
        Assert.Equal(stream.EventsAllowed, renamed.EventsAllowed);
        Assert.Equal("https://rp.example/ssf/push", renamed.EndpointUrl);

        // [] stays [] -- also when the ceiling is lowered -- and an EventsRequested the caller names is sent as given.
        SsfStream none = await ReadStream(version, new JsonArray());
        Assert.Empty(none.ToInput(new SsfStreamChanges { Description = "x" }).EventsRequested!);
        Assert.Empty(none.ToInput(new SsfStreamChanges { EventsAllowed = new[] { SsfEventType.AccountDisabled } }).EventsRequested!);
        Assert.Equal(
            new[] { SsfEventType.AccountEnabled },
            stream.ToInput(new SsfStreamChanges { EventsRequested = new[] { SsfEventType.AccountEnabled } }).EventsRequested);

        // And the whole body on the wire: the response's own string comes back byte for byte.
        Guid id = Guid.NewGuid();
        Route put = Mount("PUT", $"/api/v1/tenants/{TenantId}/ssf/streams/{id}", 200, StreamBody(version, new JsonArray()).ToJsonString());
        await Client.Ssf.UpdateStreamAsync(id, stream.ToInput(new SsfStreamChanges { EventsAllowed = new[] { SsfEventType.AccountDisabled } }));
        JsonElement sent = put.Last.Json();
        Assert.Equal(version, sent.GetProperty("expected_updated_at").GetString());
        Assert.Equal(new[] { SsfEventTypes.AccountDisabled }, sent.GetProperty("events_requested").EnumerateArray().Select(e => e.GetString()).ToArray());
        Assert.Equal(new[] { SsfEventTypes.AccountDisabled }, sent.GetProperty("events_allowed").EnumerateArray().Select(e => e.GetString()).ToArray());

        // The plain converter sends the same string, and keeps [] as [].
        Assert.Equal(version, stream.ToInput().ExpectedUpdatedAt);
        Assert.Empty(none.ToInput().EventsRequested!);
    }

    /// <summary>An assigned null for <c>expected_updated_at</c> leaves the key out; null is never sent.</summary>
    [Fact]
    public async Task AnAssignedNullExpectedUpdatedAtLeavesTheKeyOut()
    {
        SsfStream stream = await ReadStream("2026-10-05T01:02:03.123456789Z", new JsonArray(SsfEventTypes.SessionRevoked));
        Guid id = Guid.NewGuid();
        Route put = Mount("PUT", $"/api/v1/tenants/{TenantId}/ssf/streams/{id}", 200, StreamBody("2026-10-05T01:02:03Z", new JsonArray()).ToJsonString());

        SsfStreamInput none = stream.ToInput(new SsfStreamChanges { ExpectedUpdatedAt = JsonNullable<string>.Null });
        Assert.Null(none.ExpectedUpdatedAt);
        await Client.Ssf.UpdateStreamAsync(id, none);
        Assert.DoesNotContain("expected_updated_at", put.Last.Keys());
        Assert.DoesNotContain("null", put.Last.Body.Replace("\"status_reason\":null", string.Empty, StringComparison.Ordinal), StringComparison.Ordinal);

        // A value the caller names replaces the read's, as given.
        Assert.Equal("2026-01-01T00:00:00Z", stream.ToInput(new SsfStreamChanges { ExpectedUpdatedAt = "2026-01-01T00:00:00Z" }).ExpectedUpdatedAt);
        // An explicitly assigned null on the plain input is the same as never setting it.
        await Client.Ssf.UpdateStreamAsync(id, stream.ToInput() with { ExpectedUpdatedAt = null });
        Assert.DoesNotContain("expected_updated_at", put.Last.Keys());
    }

    /// <summary>The <c>update_stream</c> documentation states the three meanings (a documentation check, not a mock).</summary>
    [Fact]
    public void TheUpdateStreamDocumentationStatesTheThreeMeanings()
    {
        string source = File.ReadAllText(Path.Combine(RepositoryRoot(), "Axiam.Sdk", "Management", "SsfApi.cs"));
        int doc = source.IndexOf("UpdateStreamAsync(", StringComparison.Ordinal);
        string around = source[..doc];
        around = around[around.LastIndexOf("/// <summary>", StringComparison.Ordinal)..];
        foreach (string phrase in new[] { "absent", "resets", "events_allowed", "none", "400", "raw API client", "ToInput" })
        {
            Assert.Contains(phrase, around, StringComparison.Ordinal);
        }
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "management-registry.json")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("repository root not found");
    }
}
