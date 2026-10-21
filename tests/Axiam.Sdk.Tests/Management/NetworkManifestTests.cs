using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Options;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// CONTRACT.md &#167;27.6.2 (contract 1.62) &#8212; the <c>network</c> namespace in a manifest, and &#167;27.9's
/// "Manifest, <c>network</c>" tests, against a small stateful fake of the tenant's network.
/// </summary>
/// <remarks>
/// A stateful fake rather than the fixed-route harness, because the properties that matter &#8212; the
/// profile's <c>segment_version</c> being the <b>response</b> of the segment write that came first, an
/// <c>apply</c> followed by a <c>plan</c> being all <c>NoChange</c>, a clamped read &#8212; only mean
/// something when the second read sees what the first write did. The fake keeps the server rules the
/// manifest depends on: every write conditional on the version read (<c>409</c> with
/// <c>reason_code</c>), a profile also on the segment's version, one profile per segment, a VLAN
/// unique per site, a timeout above the cap refused <c>403</c>, and a profile read lowered to the cap.
/// </remarks>
[Trait("Category", "Fast")]
public sealed class NetworkManifestTests
{
    private static readonly Uri Base = new("https://axiam.test");
    private const string TenantSlug = "acme";
    private static readonly Guid TenantId = Guid.Parse("55555555-5555-4555-8555-555555555555");

    private static AxiamClient BuildClient(NetworkFake fake)
    {
        AxiamClient client = AxiamClient.CreateForTesting(
            Base, TenantSlug, new AxiamClientOptions { BaseUrl = Base, TenantId = TenantSlug }, fake);
        string header = B64Url(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string body = B64Url(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["sub"] = Guid.NewGuid().ToString(),
            ["org_id"] = Guid.NewGuid().ToString(),
            ["tenant_id"] = TenantId.ToString(),
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds(),
        }));
        FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        ((CookieContainer)field.GetValue(client)!).Add(Base, new Cookie("axiam_access", $"{header}.{body}.unsigned"));
        return client;
    }

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed record Recorded(string Method, string Path, string Query, string Body)
    {
        internal JsonObject Json() => JsonNode.Parse(Body)!.AsObject();

        internal IReadOnlyList<string> Keys() => Json().Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal).ToList();
    }

    private static ManifestApi Manifest(AxiamClient client) => client.Management.Manifest;

    private static ManagementManifest.NetworkSegmentSpec Lab(
        string key = "lab", int vlan = 20, params string[] filters) =>
        new(key, "hq", NetworkSegmentKind.Access, "lab", vlan, 1, filters.Length == 0 ? new[] { "lab-in", "lab-out" } : filters);

    private static ManagementManifest Full(int cap = 3600, int timeout = 1800) => new()
    {
        NetworkPolicy = new ManagementManifest.NetworkPolicySpec(cap),
        NetworkSegments = new[] { Lab() },
        NetworkProfiles = new[] { new ManagementManifest.NetworkProfileSpec("lab", timeout, FilterId: "lab-in") },
    };

    // ------------------------------------------------------------------
    // plan
    // ------------------------------------------------------------------

    /// <summary>&#167;27.6 rule 1: a plan of a policy, a segment and a profile issues <c>GET</c>s only &#8212; the policy and both lists.</summary>
    [Fact]
    public async Task PlanIssuesGetsOnlyAndReadsThePolicyAndBothLists()
    {
        var fake = new NetworkFake();
        using AxiamClient client = BuildClient(fake);

        ManagementPlan plan = await Manifest(client).PlanAsync(Full());

        Assert.All(fake.Requests, r => Assert.Equal("GET", r.Method));
        Assert.Contains(fake.Requests, r => r.Path == "/api/v1/network/policy");
        Assert.Contains(fake.Requests, r => r.Path == "/api/v1/network/segments");
        Assert.Contains(fake.Requests, r => r.Path == "/api/v1/network/profiles");
        Assert.Equal(
            new[] { (PlanChange.NoChange, PlanTarget.NetworkPolicy), (PlanChange.Create, PlanTarget.NetworkSegment), (PlanChange.Create, PlanTarget.NetworkProfile) },
            plan.Actions.Select(a => (a.Change, a.Target)).Where(t => t.Item2 >= PlanTarget.NetworkPolicy).ToArray());
    }

    /// <summary>The order is policy, segments, profiles, appended last; a manifest without a network section reads nothing of it.</summary>
    [Fact]
    public async Task TheOrderIsPolicyThenSegmentsThenProfilesAndAbsentWhenUnstated()
    {
        var fake = new NetworkFake { Cap = 3600 };
        using AxiamClient client = BuildClient(fake);
        // Raising the cap and stating a profile above the old one: the policy must come first.
        var manifest = new ManagementManifest
        {
            NetworkPolicy = new ManagementManifest.NetworkPolicySpec(7200),
            NetworkSegments = new[] { Lab("b-seg", 21, "x"), Lab("a-seg", 22, "x") with { Name = "other" } },
            NetworkProfiles = new[]
            {
                new ManagementManifest.NetworkProfileSpec("a-seg", 5000),
                new ManagementManifest.NetworkProfileSpec("b-seg", 5000),
            },
        };

        ManagementPlan plan = await Manifest(client).PlanAsync(manifest);

        Assert.Equal(
            new[] { "network.policy", "b-seg", "a-seg", "b-seg", "a-seg" },
            plan.Actions.Select(a => a.Key).ToArray());   // profiles follow their segments' order
        Assert.Equal(
            new[] { PlanTarget.NetworkPolicy, PlanTarget.NetworkSegment, PlanTarget.NetworkSegment, PlanTarget.NetworkProfile, PlanTarget.NetworkProfile },
            plan.Actions.Select(a => a.Target).ToArray());

        int before = fake.Requests.Count;
        await Manifest(client).PlanAsync(new ManagementManifest());
        Assert.DoesNotContain(fake.Requests.Skip(before), r => r.Path.StartsWith("/api/v1/network", StringComparison.Ordinal));
    }

    // ------------------------------------------------------------------
    // apply
    // ------------------------------------------------------------------

    /// <summary>On an empty tenant, apply creates the segment then the profile; the profile carries the new segment's id and the create response's version; a plan afterwards is all NoChange.</summary>
    [Fact]
    public async Task ApplyOnAnEmptyTenantCreatesSegmentThenProfileAndPlanIsThenConverged()
    {
        var fake = new NetworkFake();
        using AxiamClient client = BuildClient(fake);
        ManagementManifest manifest = Full();

        ApplyReport report = await Manifest(client).ApplyAsync(manifest);

        Assert.True(report.IsComplete, report.Failure?.Outcome.Message);
        Recorded[] writes = fake.Requests.Where(r => r.Method != "GET").ToArray();
        Assert.Equal(new[] { "POST /api/v1/network/segments", "POST /api/v1/network/profiles" }, writes.Select(w => $"{w.Method} {w.Path}").ToArray());
        JsonObject segment = fake.Segments.Single();
        JsonObject profile = writes[1].Json();
        Assert.Equal(segment["id"]!.GetValue<string>(), profile["segment_id"]!.GetValue<string>());
        Assert.Equal(segment["version"]!.GetValue<long>(), profile["segment_version"]!.GetValue<long>());   // the create response's version
        Assert.True((await Manifest(client).PlanAsync(manifest)).IsConverged, "§27.6 rule 6");
        Assert.DoesNotContain(fake.Requests, r => r.Method == "DELETE");
    }

    /// <summary>A segment Update sends the full replacement body: the version as read, the stated members, every unstated one carried, and no kind, site_key or name.</summary>
    [Fact]
    public async Task ASegmentUpdateSendsTheFullReplacementBodyCarriedFromTheRead()
    {
        var fake = new NetworkFake();
        Guid id = fake.SeedSegment("hq", "access", "lab", vlan: 20, rank: 3, filters: new[] { "lab-in", "lab-out" }, enabled: false);
        long read = fake.Segments.Single()["version"]!.GetValue<long>();
        using AxiamClient client = BuildClient(fake);
        // States only the VLAN: rank, filter_ids and enabled are silent and are carried.
        var manifest = new ManagementManifest
        {
            NetworkSegments = new[] { new ManagementManifest.NetworkSegmentSpec("lab", "hq", NetworkSegmentKind.Access, "lab", 30) },
        };

        ManagementPlan plan = await Manifest(client).PlanAsync(manifest);
        Assert.Equal(PlanChange.Update, plan.Actions.Single().Change);
        await Manifest(client).ApplyAsync(manifest);

        Recorded put = fake.Requests.Single(r => r.Method == "PUT");
        Assert.Equal($"/api/v1/network/segments/{id}", put.Path);
        Assert.Equal(new[] { "enabled", "filter_ids", "rank", "version", "vlan_id" }, put.Keys());   // no kind, site_key, name
        Assert.Equal(read, put.Json()["version"]!.GetValue<long>());
        Assert.Equal(30, put.Json()["vlan_id"]!.GetValue<int>());
        Assert.Equal(3, put.Json()["rank"]!.GetValue<int>());
        Assert.False(put.Json()["enabled"]!.GetValue<bool>());
        Assert.Equal(new[] { "lab-in", "lab-out" }, put.Json()["filter_ids"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray());
    }

    /// <summary>A stated null on an optional member leaves its key out of the body (and clears it); an unstated one is carried.</summary>
    [Fact]
    public async Task AStatedNullOnAnOptionalProfileMemberLeavesTheKeyOutAndAnUnstatedOneIsCarried()
    {
        var fake = new NetworkFake();
        Guid id = fake.SeedSegment("hq", "access", "lab", filters: new[] { "lab-in" });
        fake.SeedProfile(id, timeout: 1800, idle: 600, filter: "lab-in", service: "framed_user");
        using AxiamClient client = BuildClient(fake);
        var manifest = new ManagementManifest
        {
            NetworkSegments = new[] { Lab(filters: "lab-in") },
            NetworkProfiles = new[]
            {
                // idle_timeout_secs and filter_id stated as "none"; service_type unstated (carried).
                new ManagementManifest.NetworkProfileSpec("lab", 1800, IdleTimeoutSecs: JsonNullable<int>.Null, FilterId: JsonNullable<string>.Null),
            },
        };

        ManagementPlan plan = await Manifest(client).PlanAsync(manifest);
        Assert.Equal(PlanChange.Update, plan.Actions.Single(a => a.Target == PlanTarget.NetworkProfile).Change);
        await Manifest(client).ApplyAsync(manifest);

        Recorded put = fake.Requests.Single(r => r.Method == "PUT" && r.Path.Contains("/profiles/", StringComparison.Ordinal));
        Assert.Equal(new[] { "profile", "segment_version", "version" }, put.Keys());
        JsonObject profile = put.Json()["profile"]!.AsObject();
        Assert.Equal(new[] { "dictionary", "service_type", "session_timeout_secs", "termination_action" },
            profile.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal).ToArray());   // idle_timeout_secs and filter_id absent
        Assert.Equal("framed_user", profile["service_type"]!.GetValue<string>());
        Assert.DoesNotContain("null", put.Body, StringComparison.Ordinal);
        Assert.True((await Manifest(client).PlanAsync(manifest)).IsConverged);
    }

    /// <summary>A manifest that changes a segment and its profile sends replace_segment then replace_profile, and the profile's segment_version is the replace response's.</summary>
    [Fact]
    public async Task AProfileFollowingAChangedSegmentSendsTheReplaceResponsesVersion()
    {
        var fake = new NetworkFake();
        Guid id = fake.SeedSegment("hq", "access", "lab", vlan: 20, filters: new[] { "lab-in", "lab-out" });
        fake.SeedProfile(id, timeout: 600, filter: "lab-in");
        long readSegmentVersion = fake.Segments.Single()["version"]!.GetValue<long>();
        using AxiamClient client = BuildClient(fake);
        var manifest = new ManagementManifest
        {
            NetworkSegments = new[] { Lab(vlan: 40) },
            NetworkProfiles = new[] { new ManagementManifest.NetworkProfileSpec("lab", 900, FilterId: "lab-in") },
        };

        ApplyReport report = await Manifest(client).ApplyAsync(manifest);

        Assert.True(report.IsComplete, report.Failure?.Outcome.Message);
        Recorded[] puts = fake.Requests.Where(r => r.Method == "PUT").ToArray();
        Assert.Equal(2, puts.Length);
        Assert.Contains("/segments/", puts[0].Path, StringComparison.Ordinal);
        Assert.Contains("/profiles/", puts[1].Path, StringComparison.Ordinal);
        long afterReplace = fake.Segments.Single()["version"]!.GetValue<long>();
        Assert.NotEqual(readSegmentVersion, afterReplace);
        Assert.Equal(afterReplace, puts[1].Json()["segment_version"]!.GetValue<long>());   // not the one plan read
        Assert.True((await Manifest(client).PlanAsync(manifest)).IsConverged);
    }

    /// <summary>A policy Update sends the version read; the cap is written before a profile that needs it.</summary>
    [Fact]
    public async Task ThePolicyIsWrittenFirstWithTheVersionReadSoAHigherProfileLands()
    {
        var fake = new NetworkFake { Cap = 3600, PolicyVersion = 5 };
        using AxiamClient client = BuildClient(fake);
        var manifest = new ManagementManifest
        {
            NetworkPolicy = new ManagementManifest.NetworkPolicySpec(7200),
            NetworkSegments = new[] { Lab() },
            NetworkProfiles = new[] { new ManagementManifest.NetworkProfileSpec("lab", 5000) },
        };

        ApplyReport report = await Manifest(client).ApplyAsync(manifest);

        Assert.True(report.IsComplete, report.Failure?.Outcome.Message);
        Recorded[] writes = fake.Requests.Where(r => r.Method != "GET").ToArray();
        Assert.Equal("PUT /api/v1/network/policy", $"{writes[0].Method} {writes[0].Path}");
        Assert.Equal(new[] { "session_timeout_max_secs", "version" }, writes[0].Keys());
        Assert.Equal(5, writes[0].Json()["version"]!.GetValue<long>());
        Assert.Equal(7200, fake.Cap);
        Assert.True((await Manifest(client).PlanAsync(manifest)).IsConverged);
    }

    // ------------------------------------------------------------------
    // conflicts and refusals
    // ------------------------------------------------------------------

    /// <summary>A 409 stale_version on a network write makes one request, stops the apply, and the outcome exposes reason_code; so does duplicate_vlan.</summary>
    [Fact]
    public async Task AConflictIsOneRequestStopsTheApplyAndExposesTheReasonCode()
    {
        var fake = new NetworkFake();
        Guid id = fake.SeedSegment("hq", "access", "lab", vlan: 20);
        fake.SeedSegment("hq", "access", "other", vlan: 40, rank: 2);
        fake.RaceVersionOnNextSegmentWrite = true;   // another administrator writes between the plan and the write
        using AxiamClient client = BuildClient(fake);
        var manifest = new ManagementManifest
        {
            NetworkSegments = new[] { Lab(vlan: 30), new ManagementManifest.NetworkSegmentSpec("late", "hq", NetworkSegmentKind.Access, "late", 50, 9) },
            NetworkProfiles = new[] { new ManagementManifest.NetworkProfileSpec("lab", 600) },
        };

        ApplyReport report = await Manifest(client).ApplyAsync(manifest);

        Assert.False(report.IsComplete);
        AppliedStep failure = report.Failure!;
        Assert.Equal(PlanTarget.NetworkSegment, failure.Action.Target);
        Assert.Equal("stale_version", failure.Outcome.ReasonCode);
        Assert.Equal(1, fake.Requests.Count(r => r.Method == "PUT"));                   // exactly one request, no retry, no re-read
        Assert.DoesNotContain(fake.Requests, r => r.Method == "POST");                   // later actions were not attempted
        Assert.All(report.Steps.SkipWhile(s => s != failure).Skip(1), s => Assert.Equal(ApplyStatus.NotAttempted, s.Outcome.Status));

        // already_exists / duplicate_vlan: the same shape.
        var second = new NetworkFake();
        second.SeedSegment("hq", "access", "taken", vlan: 20, rank: 7);
        using AxiamClient other = BuildClient(second);
        ApplyReport duplicate = await Manifest(other).ApplyAsync(new ManagementManifest { NetworkSegments = new[] { Lab(vlan: 20) } });
        Assert.Equal("duplicate_vlan", duplicate.Failure!.Outcome.ReasonCode);
        Assert.Equal(1, second.Requests.Count(r => r.Method == "POST"));
    }

    /// <summary>Pruning is off: a segment the manifest omits is never deleted, and the policy is never deleted.</summary>
    [Fact]
    public async Task NothingIsEverDeletedByAMissingSpec()
    {
        var fake = new NetworkFake();
        Guid kept = fake.SeedSegment("hq", "access", "lab", vlan: 20);
        fake.SeedSegment("hq", "access", "stray", vlan: 99, rank: 9);
        fake.SeedProfile(kept, timeout: 600);
        using AxiamClient client = BuildClient(fake);
        var manifest = new ManagementManifest { NetworkSegments = new[] { Lab(filters: "lab-in", vlan: 20) with { Rank = 1 } } };

        ManagementPlan plan = await Manifest(client).PlanAsync(manifest);
        await Manifest(client).ApplyAsync(manifest);

        Assert.DoesNotContain(plan.Actions, a => a.Summary.Contains("stray", StringComparison.Ordinal));
        Assert.DoesNotContain(fake.Requests, r => r.Method == "DELETE");
        Assert.Equal(2, fake.Segments.Count);
    }

    /// <summary>A natural key named twice, a dangling profile, and a repeated Filter-Id are each refused with zero wire calls, at plan and at apply.</summary>
    [Fact]
    public async Task InvalidNetworkSectionsAreRefusedBeforeAnyRequest()
    {
        var fake = new NetworkFake();
        using AxiamClient client = BuildClient(fake);
        var cases = new Dictionary<string, ManagementManifest>
        {
            ["twice"] = new() { NetworkSegments = new[] { Lab("a"), Lab("b") } },
            ["dangling"] = new()
            {
                NetworkSegments = new[] { Lab() },
                NetworkProfiles = new[] { new ManagementManifest.NetworkProfileSpec("nope", 600) },
            },
            ["two-profiles"] = new()
            {
                NetworkSegments = new[] { Lab() },
                NetworkProfiles = new[] { new ManagementManifest.NetworkProfileSpec("lab", 600), new ManagementManifest.NetworkProfileSpec("lab", 900) },
            },
            ["repeated-filter"] = new() { NetworkSegments = new[] { Lab(filters: new[] { "x", "y", "x" }) } },
            ["unknown-kind"] = new()
            {
                NetworkSegments = new[] { new ManagementManifest.NetworkSegmentSpec("u", "hq", NetworkSegmentKind.Unknown, "u", 5) },
            },
        };

        foreach ((string name, ManagementManifest manifest) in cases)
        {
            await Assert.ThrowsAsync<NetworkError>(() => Manifest(client).PlanAsync(manifest));
            await Assert.ThrowsAsync<NetworkError>(() => Manifest(client).ApplyAsync(manifest));
            Assert.True(fake.Requests.Count == 0, $"case '{name}' reached the wire");
        }

        // The builder says so too: a second policy, and a profile for a segment not declared.
        Assert.Throws<NetworkError>(() => ManagementManifest.Builder().NetworkPolicy(600).NetworkPolicy(900).Build());
        Assert.Throws<NetworkError>(() => ManagementManifest.Builder().NetworkProfile("nope", 600).Build());
    }

    // ------------------------------------------------------------------
    // kind, filter_ids, the clamped profile
    // ------------------------------------------------------------------

    /// <summary>The kind is the wire spelling: stated access is NoChange against a read of "access", and the create body carries it; no zones anywhere.</summary>
    [Fact]
    public async Task TheKindIsTheWireSpellingAndThereIsNoZones()
    {
        var fake = new NetworkFake();
        fake.SeedSegment("hq", "access", "lab", vlan: 20, rank: 1, filters: new[] { "lab-in", "lab-out" });
        using AxiamClient client = BuildClient(fake);

        ManagementPlan same = await Manifest(client).PlanAsync(new ManagementManifest { NetworkSegments = new[] { Lab() } });
        Assert.Equal(PlanChange.NoChange, same.Actions.Single().Change);

        var quarantine = new ManagementManifest.NetworkSegmentSpec("q", "hq", NetworkSegmentKind.Quarantine, "jail", 666);
        await Manifest(client).ApplyAsync(new ManagementManifest { NetworkSegments = new[] { quarantine } });
        Recorded created = fake.Requests.Single(r => r.Method == "POST");
        Assert.Equal("quarantine", created.Json()["kind"]!.GetValue<string>());
        Assert.DoesNotContain(fake.Requests, r => r.Path.Contains("zones", StringComparison.Ordinal) || r.Body.Contains("zones", StringComparison.Ordinal));
        Assert.DoesNotContain("zones", ManagementManifest.Builder().NetworkSegment("s", "hq", NetworkSegmentKind.Access, "n", 1).Build().NetworkSegments[0].ToString()!, StringComparison.Ordinal);
    }

    /// <summary>filter_ids is a set: a reorder is NoChange and writes nothing; another member's Update, and a Create, send the order the manifest states.</summary>
    [Fact]
    public async Task FilterIdsAreComparedAsASetAndWrittenInTheStatedOrder()
    {
        var fake = new NetworkFake();
        fake.SeedSegment("hq", "access", "lab", vlan: 20, rank: 1, filters: new[] { "lab-in", "lab-out" });
        using AxiamClient client = BuildClient(fake);

        var reordered = new ManagementManifest { NetworkSegments = new[] { Lab(filters: new[] { "lab-out", "lab-in" }) } };
        ManagementPlan plan = await Manifest(client).PlanAsync(reordered);
        Assert.Equal(PlanChange.NoChange, plan.Actions.Single().Change);
        await Manifest(client).ApplyAsync(reordered);
        Assert.DoesNotContain(fake.Requests, r => r.Method != "GET");

        // Another member differs: the Update sends filter_ids in the order stated (not the read's).
        var changed = new ManagementManifest { NetworkSegments = new[] { Lab(vlan: 21, filters: new[] { "lab-out", "lab-in" }) } };
        await Manifest(client).ApplyAsync(changed);
        Recorded put = fake.Requests.Single(r => r.Method == "PUT");
        Assert.Equal(new[] { "lab-out", "lab-in" }, put.Json()["filter_ids"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray());

        // And a Create does the same.
        var created = new ManagementManifest.NetworkSegmentSpec("n", "hq", NetworkSegmentKind.Access, "fresh", 77, 5, new[] { "z", "a", "m" });
        await Manifest(client).ApplyAsync(new ManagementManifest { NetworkSegments = new[] { created } });
        Recorded post = fake.Requests.Single(r => r.Method == "POST");
        Assert.Equal(new[] { "z", "a", "m" }, post.Json()["filter_ids"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray());
    }

    /// <summary>&#167;27.6.2 item 4 (C162-06): an <c>Update</c> that would carry an unknown open-enum value of the read is refused at <c>plan</c>, with no write; stating the member resolves it; a <c>NoChange</c> is not refused.</summary>
    [Theory]
    [InlineData("termination_action")]
    [InlineData("service_type")]
    public async Task APlanRefusesAnUpdateThatWouldCarryAnUnknownOpenEnumValueTheManifestDoesNotState(string member)
    {
        var fake = new NetworkFake();
        Guid id = fake.SeedSegment("hq", "access", "lab", vlan: 20, rank: 1, filters: new[] { "lab-in", "lab-out" });
        if (member == "termination_action")
        {
            fake.SeedProfile(id, timeout: 600, filter: "lab-in", termination: "future");
        }
        else
        {
            fake.SeedProfile(id, timeout: 600, filter: "lab-in", service: "future_service");
        }

        using AxiamClient client = BuildClient(fake);

        ManagementManifest Changing(RadiusTerminationAction? termination = null, JsonNullable<RadiusServiceType>? service = null) => new()
        {
            NetworkSegments = new[] { Lab() },
            NetworkProfiles = new[]
            {
                new ManagementManifest.NetworkProfileSpec("lab", 900, termination, FilterId: "lab-in", ServiceType: service),
            },
        };

        // Another member differs and the unknown one is not stated: refused, naming the member, no write.
        NetworkError refused = await Assert.ThrowsAsync<NetworkError>(() => Manifest(client).PlanAsync(Changing()));
        Assert.Contains(member, refused.Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<NetworkError>(() => Manifest(client).ApplyAsync(Changing()));
        Assert.DoesNotContain(fake.Requests, r => r.Method != "GET");

        // Stating the member resolves it: an Update whose body carries the stated value, never the unknown one.
        ManagementManifest stated = member == "termination_action"
            ? Changing(termination: RadiusTerminationAction.RadiusRequest)
            : Changing(service: JsonNullable<RadiusServiceType>.Of(RadiusServiceType.FramedUser));
        ManagementPlan plan = await Manifest(client).PlanAsync(stated);
        Assert.Equal(PlanChange.Update, plan.Actions.Single(a => a.Target == PlanTarget.NetworkProfile).Change);
        await Manifest(client).ApplyAsync(stated);
        Recorded put = fake.Requests.Single(r => r.Method == "PUT" && r.Path.Contains("/profiles/", StringComparison.Ordinal));
        Assert.DoesNotContain("future", put.Body, StringComparison.Ordinal);
    }

    /// <summary>&#167;27.6.2 item 4: a profile with an unknown open-enum value that nothing differs from is <c>NoChange</c>, not refused, and writes nothing.</summary>
    [Fact]
    public async Task AnUnknownOpenEnumValueIsNotRefusedWhenNothingDiffers()
    {
        var fake = new NetworkFake();
        Guid id = fake.SeedSegment("hq", "access", "lab", vlan: 20, rank: 1, filters: new[] { "lab-in", "lab-out" });
        fake.SeedProfile(id, timeout: 600, filter: "lab-in", termination: "future");
        using AxiamClient client = BuildClient(fake);

        var manifest = new ManagementManifest
        {
            NetworkSegments = new[] { Lab() },
            NetworkProfiles = new[] { new ManagementManifest.NetworkProfileSpec("lab", 600, FilterId: "lab-in") },
        };
        ManagementPlan plan = await Manifest(client).PlanAsync(manifest);
        Assert.Equal(PlanChange.NoChange, plan.Actions.Single(a => a.Target == PlanTarget.NetworkProfile).Change);
        await Manifest(client).ApplyAsync(manifest);
        Assert.DoesNotContain(fake.Requests, r => r.Method != "GET");
    }

    /// <summary>A clamped profile: stating the cap is NoChange; stating above it is an Update whose apply sends one replace, meets 403, stops without retry, and carries the server's message.</summary>
    [Fact]
    public async Task AClampedProfileIsJudgedOnTheReadAndAValueAboveTheCapIsTheActionsFailure()
    {
        var fake = new NetworkFake { Cap = 900 };
        Guid id = fake.SeedSegment("hq", "access", "lab", vlan: 20, rank: 1, filters: new[] { "lab-in", "lab-out" });
        fake.SeedProfile(id, timeout: 3600, filter: "lab-in");   // stored above the lowered cap: it reads as 900, clamped
        fake.SeedSegment("hq", "access", "later", vlan: 21, rank: 2);
        using AxiamClient client = BuildClient(fake);

        ManagementManifest Stating(int timeout) => new()
        {
            NetworkSegments = new[] { Lab(), new ManagementManifest.NetworkSegmentSpec("later", "hq", NetworkSegmentKind.Access, "later", 22, 2) },
            NetworkProfiles = new[] { new ManagementManifest.NetworkProfileSpec("lab", timeout, FilterId: "lab-in") },
        };

        ManagementPlan atCap = await Manifest(client).PlanAsync(Stating(900));
        Assert.Equal(PlanChange.NoChange, atCap.Actions.Single(a => a.Target == PlanTarget.NetworkProfile).Change);
        await Manifest(client).ApplyAsync(new ManagementManifest { NetworkSegments = Stating(900).NetworkSegments, NetworkProfiles = Stating(900).NetworkProfiles });
        Assert.DoesNotContain(fake.Requests, r => r.Path.Contains("/profiles/", StringComparison.Ordinal) && r.Method == "PUT");

        // Above the cap: an Update in plan.
        ManagementPlan above = await Manifest(client).PlanAsync(Stating(3600));
        Assert.Equal(PlanChange.Update, above.Actions.Single(a => a.Target == PlanTarget.NetworkProfile).Change);

        int mark = fake.Requests.Count;
        ApplyReport report = await Manifest(client).ApplyAsync(Stating(3600));

        Recorded[] sent = fake.Requests.Skip(mark).Where(r => r.Method != "GET").ToArray();
        // The profile's replace is the only write the second apply makes, and the server refuses it.
        Recorded profileWrite = Assert.Single(sent, r => r.Path.Contains("/profiles/", StringComparison.Ordinal));
        Assert.Equal(1, sent.Count(r => r.Path.Contains("/profiles/", StringComparison.Ordinal)));   // no retry
        Assert.Equal(3600, profileWrite.Json()["profile"]!["session_timeout_secs"]!.GetValue<int>());   // not lowered by the SDK
        AppliedStep failure = report.Failure!;
        Assert.Equal(PlanTarget.NetworkProfile, failure.Action.Target);
        Assert.Contains("session_timeout_secs is above the tenant's cap of 900", failure.Outcome.Message, StringComparison.Ordinal);
        Assert.Null(failure.Outcome.ReasonCode);
        Assert.All(report.Steps.SkipWhile(s => s != failure).Skip(1), s => Assert.Equal(ApplyStatus.NotAttempted, s.Outcome.Status));
    }

    // ------------------------------------------------------------------
    // The fake
    // ------------------------------------------------------------------

    private sealed class NetworkFake : HttpMessageHandler
    {
        private const string Now = "2026-10-16T00:00:00Z";

        internal readonly List<JsonObject> Segments = new();
        internal readonly List<JsonObject> Profiles = new();
        internal readonly List<Recorded> Requests = new();

        internal int Cap = 3600;
        internal long PolicyVersion;

        /// <summary>Bumps the next segment row's version just before that write is judged &#8212; another administrator wrote.</summary>
        internal bool RaceVersionOnNextSegmentWrite;

        internal Guid SeedSegment(
            string site, string kind, string name, int vlan = 10, int? rank = null, string[]? filters = null, bool enabled = true)
        {
            Guid id = Guid.NewGuid();
            Segments.Add(new JsonObject
            {
                ["id"] = id.ToString(),
                ["tenant_id"] = TenantId.ToString(),
                ["path"] = $"/network/{(kind == "access" ? "zones" : "quarantine")}/{site}/{name}",
                ["name"] = name,
                ["site_key"] = site,
                ["kind"] = kind,
                ["vlan_id"] = vlan,
                ["filter_ids"] = new JsonArray((filters ?? Array.Empty<string>()).Select(f => (JsonNode)JsonValue.Create(f)!).ToArray()),
                ["rank"] = kind == "access" ? rank ?? 1 : null,
                ["enabled"] = enabled,
                ["version"] = 1L,
                ["created_by"] = Guid.NewGuid().ToString(),
                ["updated_by"] = Guid.NewGuid().ToString(),
                ["created_at"] = Now,
                ["updated_at"] = Now,
            });
            return id;
        }

        internal void SeedProfile(Guid segment, int timeout, int? idle = null, string? filter = null, string? service = null, string termination = "radius_request")
        {
            Profiles.Add(new JsonObject
            {
                ["segment_id"] = segment.ToString(),
                ["tenant_id"] = TenantId.ToString(),
                ["dictionary"] = "axiam-radius-reply/1",
                ["stored_timeout"] = timeout,
                ["termination_action"] = termination,
                ["idle_timeout_secs"] = idle,
                ["filter_id"] = filter,
                ["service_type"] = service,
                ["version"] = 1L,
                ["created_by"] = Guid.NewGuid().ToString(),
                ["updated_by"] = Guid.NewGuid().ToString(),
                ["created_at"] = Now,
                ["updated_at"] = Now,
            });
        }

        private JsonObject Effective(JsonObject stored)
        {
            var read = (JsonObject)stored.DeepClone();
            int storedTimeout = read["stored_timeout"]!.GetValue<int>();
            read.Remove("stored_timeout");
            read["session_timeout_secs"] = Math.Min(storedTimeout, Cap);
            read["session_timeout_clamped"] = storedTimeout > Cap;
            return read;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            var recorded = new Recorded(request.Method.Method, request.RequestUri!.AbsolutePath, request.RequestUri.Query, body);
            Requests.Add(recorded);
            return Handle(recorded);
        }

        private static HttpResponseMessage Json(HttpStatusCode status, JsonNode? node) =>
            new(status) { Content = new StringContent(node?.ToJsonString() ?? string.Empty, Encoding.UTF8, "application/json") };

        private static HttpResponseMessage Page(IEnumerable<JsonNode> items) =>
            Json(HttpStatusCode.OK, new JsonObject
            {
                ["items"] = new JsonArray(items.Select(i => i.DeepClone()).ToArray()),
                ["total"] = items.Count(),
                ["offset"] = 0,
                ["limit"] = 200,
            });

        private static HttpResponseMessage Conflict(string error, string reason) =>
            Json(HttpStatusCode.Conflict, new JsonObject { ["error"] = error, ["message"] = $"conflict: {reason}", ["reason_code"] = reason });

        private HttpResponseMessage Handle(Recorded r)
        {
            string path = r.Path;
            if (r.Method == "GET" && path is "/api/v1/resources" or "/api/v1/permissions" or "/api/v1/roles" or "/api/v1/groups" or "/api/v1/users")
            {
                return Page(Array.Empty<JsonNode>());
            }

            if (path == "/api/v1/network/policy")
            {
                if (r.Method == "GET")
                {
                    return Json(HttpStatusCode.OK, PolicyNode());
                }

                JsonObject sent = r.Json();
                if (sent["version"]!.GetValue<long>() != PolicyVersion)
                {
                    return Conflict("conflict", "stale_version");
                }

                Cap = sent["session_timeout_max_secs"]!.GetValue<int>();
                PolicyVersion++;
                return Json(HttpStatusCode.OK, PolicyNode());
            }

            if (path == "/api/v1/network/segments")
            {
                return r.Method == "GET" ? Page(Segments) : CreateSegment(r.Json());
            }

            if (path.StartsWith("/api/v1/network/segments/", StringComparison.Ordinal))
            {
                JsonObject? segment = Segments.FirstOrDefault(s => path.EndsWith(s["id"]!.GetValue<string>(), StringComparison.Ordinal));
                return segment is null ? Json(HttpStatusCode.NotFound, new JsonObject { ["error"] = "not_found" })
                    : r.Method == "GET" ? Json(HttpStatusCode.OK, segment) : ReplaceSegment(segment, r.Json());
            }

            if (path == "/api/v1/network/profiles")
            {
                return r.Method == "GET" ? Page(Profiles.Select(Effective)) : CreateProfile(r.Json());
            }

            if (path.StartsWith("/api/v1/network/profiles/", StringComparison.Ordinal))
            {
                JsonObject? profile = Profiles.FirstOrDefault(p => path.EndsWith(p["segment_id"]!.GetValue<string>(), StringComparison.Ordinal));
                return profile is null ? Json(HttpStatusCode.NotFound, new JsonObject { ["error"] = "not_found" })
                    : r.Method == "GET" ? Json(HttpStatusCode.OK, Effective(profile)) : ReplaceProfile(profile, r.Json());
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private JsonNode PolicyNode() => new JsonObject
        {
            ["tenant_id"] = TenantId.ToString(),
            ["session_timeout_max_secs"] = Cap,
            ["version"] = PolicyVersion,
        };

        private HttpResponseMessage CreateSegment(JsonObject sent)
        {
            string site = sent["site_key"]!.GetValue<string>();
            if (Segments.Any(s => s["site_key"]!.GetValue<string>() == site && s["vlan_id"]!.GetValue<int>() == sent["vlan_id"]!.GetValue<int>()))
            {
                return Conflict("already_exists", "duplicate_vlan");
            }

            Guid id = SeedSegment(
                site, sent["kind"]!.GetValue<string>(), sent["name"]!.GetValue<string>(), sent["vlan_id"]!.GetValue<int>(),
                sent["rank"]?.GetValue<int>(),
                sent["filter_ids"]?.AsArray().Select(n => n!.GetValue<string>()).ToArray(),
                sent["enabled"]?.GetValue<bool>() ?? true);
            return Json(HttpStatusCode.Created, Segments.Single(s => s["id"]!.GetValue<string>() == id.ToString()));
        }

        private HttpResponseMessage ReplaceSegment(JsonObject segment, JsonObject sent)
        {
            if (RaceVersionOnNextSegmentWrite)
            {
                RaceVersionOnNextSegmentWrite = false;
                segment["version"] = segment["version"]!.GetValue<long>() + 1L;
            }

            if (sent["version"]!.GetValue<long>() != segment["version"]!.GetValue<long>())
            {
                return Conflict("conflict", "stale_version");
            }

            segment["vlan_id"] = sent["vlan_id"]!.GetValue<int>();
            segment["filter_ids"] = sent["filter_ids"]!.DeepClone();
            segment["enabled"] = sent["enabled"]!.GetValue<bool>();
            segment["rank"] = sent["rank"]?.GetValue<int>();
            segment["version"] = segment["version"]!.GetValue<long>() + 1L;
            return Json(HttpStatusCode.OK, segment);
        }

        private HttpResponseMessage CreateProfile(JsonObject sent)
        {
            string segmentId = sent["segment_id"]!.GetValue<string>();
            JsonObject? segment = Segments.FirstOrDefault(s => s["id"]!.GetValue<string>() == segmentId);
            if (segment is null)
            {
                return Json(HttpStatusCode.NotFound, new JsonObject { ["error"] = "not_found" });
            }

            if (Profiles.Any(p => p["segment_id"]!.GetValue<string>() == segmentId))
            {
                return Conflict("already_exists", "profile_exists");
            }

            if (sent["segment_version"]!.GetValue<long>() != segment["version"]!.GetValue<long>())
            {
                return Conflict("conflict", "stale_version");
            }

            JsonObject input = sent["profile"]!.AsObject();
            if (input["session_timeout_secs"]!.GetValue<int>() > Cap)
            {
                return AboveCap();
            }

            SeedProfile(Guid.Parse(segmentId), input["session_timeout_secs"]!.GetValue<int>(),
                input["idle_timeout_secs"]?.GetValue<int>(), input["filter_id"]?.GetValue<string>(), input["service_type"]?.GetValue<string>());
            return Json(HttpStatusCode.Created, Effective(Profiles.Last()));
        }

        private HttpResponseMessage ReplaceProfile(JsonObject profile, JsonObject sent)
        {
            JsonObject segment = Segments.Single(s => s["id"]!.GetValue<string>() == profile["segment_id"]!.GetValue<string>());
            if (sent["version"]!.GetValue<long>() != profile["version"]!.GetValue<long>()
                || sent["segment_version"]!.GetValue<long>() != segment["version"]!.GetValue<long>())
            {
                return Conflict("conflict", "stale_version");
            }

            JsonObject input = sent["profile"]!.AsObject();
            if (input["session_timeout_secs"]!.GetValue<int>() > Cap)
            {
                return AboveCap();
            }

            profile["stored_timeout"] = input["session_timeout_secs"]!.GetValue<int>();
            profile["idle_timeout_secs"] = input["idle_timeout_secs"]?.GetValue<int>();
            profile["filter_id"] = input["filter_id"]?.GetValue<string>();
            profile["service_type"] = input["service_type"]?.GetValue<string>();
            profile["version"] = profile["version"]!.GetValue<long>() + 1;
            return Json(HttpStatusCode.OK, Effective(profile));
        }

        /// <summary>The write gate's H3: a value rule answered as a 403 with a message and neither action nor resource_id.</summary>
        private HttpResponseMessage AboveCap() =>
            Json(HttpStatusCode.Forbidden, new JsonObject
            {
                ["error"] = "authorization_denied",
                ["message"] = $"session_timeout_secs is above the tenant's cap of {Cap}",
            });
    }
}
