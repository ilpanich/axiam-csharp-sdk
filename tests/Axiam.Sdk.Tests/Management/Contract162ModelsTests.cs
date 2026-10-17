using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Ssf;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// CONTRACT.md contract 1.62: the <c>network</c> namespace (&#167;36.8, its five required tests), the
/// change-taking form of an SSF stream (&#167;32.2, &#167;32.8 test 7), the request <c>user_id</c> as an
/// untyped string and an assigned <c>null</c> as "none" (&#167;27.11 rule 5, items (f) and (i)), and
/// <c>expected_updated_at</c> as the response's own string (item (g)).
/// </summary>
[Trait("Category", "Fast")]
public sealed class Contract162ModelsTests : ManagementTestBase
{
    private static readonly Guid SegmentId = Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");

    private static string Segments => "/api/v1/network/segments";

    private static string Profiles => "/api/v1/network/profiles";

    private static string Policy => "/api/v1/network/policy";

    private static JsonObject SegmentBody(string kind = "access", long version = 4, int? rank = 1) => new()
    {
        ["id"] = SegmentId.ToString(),
        ["tenant_id"] = TenantId.ToString(),
        ["path"] = "/network/zones/hq/lab",
        ["name"] = "lab",
        ["site_key"] = "hq",
        ["kind"] = kind,
        ["vlan_id"] = 20,
        ["filter_ids"] = new JsonArray("lab-in", "lab-out"),
        ["rank"] = rank,
        ["enabled"] = true,
        ["version"] = version,
        ["created_by"] = ExampleId.ToString(),
        ["updated_by"] = ExampleId.ToString(),
        ["created_at"] = "2026-10-16T00:00:00Z",
        ["updated_at"] = "2026-10-16T00:00:00Z",
    };

    private static JsonObject ProfileBody(
        string termination = "radius_request", string? service = "framed_user", bool clamped = false, int timeout = 3600) => new()
    {
        ["segment_id"] = SegmentId.ToString(),
        ["tenant_id"] = TenantId.ToString(),
        ["dictionary"] = "axiam-radius-reply/1",
        ["session_timeout_secs"] = timeout,
        ["session_timeout_clamped"] = clamped,
        ["termination_action"] = termination,
        ["idle_timeout_secs"] = 600,
        ["filter_id"] = "lab-in",
        ["service_type"] = service,
        ["version"] = 7,
        ["created_by"] = ExampleId.ToString(),
        ["updated_by"] = ExampleId.ToString(),
        ["created_at"] = "2026-10-16T00:00:00Z",
        ["updated_at"] = "2026-10-16T00:00:00Z",
    };

    private static JsonObject PolicyBody(long version = 3) => new()
    {
        ["tenant_id"] = TenantId.ToString(),
        ["session_timeout_max_secs"] = 3600,
        ["version"] = version,
    };

    private static string PageJson(JsonObject item, int total = 1) =>
        $$"""{"items":[{{item.ToJsonString()}}],"total":{{total}},"offset":0,"limit":200}""";

    // ------------------------------------------------------------------
    // §36.8 test 1 — the surface
    // ------------------------------------------------------------------

    /// <summary>The twelve operations exist with the paths and methods of &#167;36.1, and nothing reaches the decision route.</summary>
    [Fact]
    public async Task TheTwelveOperationsExistWithTheirPathsAndNoneReachesTheDecisionRoute()
    {
        Route listSegments = Mount("GET", Segments, 200, PageJson(SegmentBody()));
        Route createSegment = Mount("POST", Segments, 201, SegmentBody().ToJsonString());
        Route getSegment = Mount("GET", $"{Segments}/{SegmentId}", 200, SegmentBody().ToJsonString());
        Route replaceSegment = Mount("PUT", $"{Segments}/{SegmentId}", 200, SegmentBody().ToJsonString());
        Route deleteSegment = Mount("DELETE", $"{Segments}/{SegmentId}", 204, string.Empty);
        Route listProfiles = Mount("GET", Profiles, 200, PageJson(ProfileBody()));
        Route createProfile = Mount("POST", Profiles, 201, ProfileBody().ToJsonString());
        Route getProfile = Mount("GET", $"{Profiles}/{SegmentId}", 200, ProfileBody().ToJsonString());
        Route replaceProfile = Mount("PUT", $"{Profiles}/{SegmentId}", 200, ProfileBody().ToJsonString());
        Route deleteProfile = Mount("DELETE", $"{Profiles}/{SegmentId}", 204, string.Empty);
        Route getPolicy = Mount("GET", Policy, 200, PolicyBody().ToJsonString());
        Route replacePolicy = Mount("PUT", Policy, 200, PolicyBody(4).ToJsonString());

        NetworkApi network = Client.Network;
        Assert.Equal(0, TotalCalls());   // acquiring the handle performs no I/O (§27.2 rule 1)

        await network.ListSegmentsAsync();
        await network.CreateSegmentAsync(NewSegment());
        await network.GetSegmentAsync(SegmentId);
        await network.ReplaceSegmentAsync(SegmentId, new ReplaceNetworkSegmentRequest { Version = 4, VlanId = 20, FilterIds = Array.Empty<string>(), Enabled = true });
        await network.DeleteSegmentAsync(SegmentId, 4);
        await network.ListProfilesAsync();
        await network.CreateProfileAsync(new CreateNetworkReplyProfileRequest { SegmentId = SegmentId, SegmentVersion = 4, Profile = new NetworkReplyProfileInput { SessionTimeoutSecs = 3600 } });
        await network.GetProfileAsync(SegmentId);
        await network.ReplaceProfileAsync(SegmentId, new ReplaceNetworkReplyProfileRequest { Version = 7, SegmentVersion = 4, Profile = new NetworkReplyProfileInput { SessionTimeoutSecs = 3600 } });
        await network.DeleteProfileAsync(SegmentId, 7);
        await network.GetPolicyAsync();
        await network.ReplacePolicyAsync(new ReplaceNetworkPolicyRequest { SessionTimeoutMaxSecs = 3600, Version = 3 });

        foreach (Route route in new[]
                 {
                     listSegments, createSegment, getSegment, replaceSegment, deleteSegment, listProfiles,
                     createProfile, getProfile, replaceProfile, deleteProfile, getPolicy, replacePolicy,
                 })
        {
            Assert.Equal(1, route.Calls);
        }

        // No method of the handle, generated or hand-written, names the decision route.
        string[] expected =
        {
            "CreateProfileAsync", "CreateSegmentAsync", "DeleteProfileAsync", "DeleteSegmentAsync",
            "GetPolicyAsync", "GetProfileAsync", "GetSegmentAsync", "ListProfilesAllAsync", "ListProfilesAsync",
            "ListSegmentsAllAsync", "ListSegmentsAsync", "ReplacePolicyAsync", "ReplaceProfileAsync",
            "ReplaceSegmentAsync",
        };
        string[] actual = typeof(NetworkApi)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(m => m.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        Assert.Equal(expected, actual);
        Assert.DoesNotContain(actual, n => n.Contains("Decide", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(ExpectedSurface(), n => n.StartsWith("network.", StringComparison.Ordinal) && n.Contains("decide", StringComparison.Ordinal));
        Assert.Equal(12, ExpectedSurface().Count(n => n.StartsWith("network.", StringComparison.Ordinal)));
        Assert.Empty(Unmatched());
    }

    private static CreateNetworkSegmentRequest NewSegment() => new()
    {
        Kind = NetworkSegmentKind.Access, SiteKey = "hq", Name = "lab", VlanId = 20,
    };

    // ------------------------------------------------------------------
    // §36.8 test 2 — versions, and the 409 with its reason_code
    // ------------------------------------------------------------------

    /// <summary>Every version is sent exactly as given, and a delete cannot be called without one.</summary>
    [Fact]
    public async Task VersionsAreSentExactlyAsGivenAndADeleteCannotBeCalledWithoutOne()
    {
        Route replaceSegment = Mount("PUT", $"{Segments}/{SegmentId}", 200, SegmentBody().ToJsonString());
        Route deleteSegment = Mount("DELETE", $"{Segments}/{SegmentId}", 204, string.Empty);
        Route deleteProfile = Mount("DELETE", $"{Profiles}/{SegmentId}", 204, string.Empty);
        Route createProfile = Mount("POST", Profiles, 201, ProfileBody().ToJsonString());
        Route replaceProfile = Mount("PUT", $"{Profiles}/{SegmentId}", 200, ProfileBody().ToJsonString());
        Route replacePolicy = Mount("PUT", Policy, 200, PolicyBody().ToJsonString());

        await Client.Network.ReplaceSegmentAsync(SegmentId, new ReplaceNetworkSegmentRequest
        {
            Version = 4_000_000_000L, VlanId = 20, FilterIds = Array.Empty<string>(), Enabled = true,
        });
        Assert.Equal(4_000_000_000L, replaceSegment.Last.Json().GetProperty("version").GetInt64());

        await Client.Network.DeleteSegmentAsync(SegmentId, 9);
        Assert.Equal("9", deleteSegment.Last.Query["version"]);
        await Client.Network.DeleteProfileAsync(SegmentId, 0);
        Assert.Equal("0", deleteProfile.Last.Query["version"]);

        foreach (string name in new[] { "DeleteSegmentAsync", "DeleteProfileAsync" })
        {
            ParameterInfo version = typeof(NetworkApi).GetMethod(name)!.GetParameters().Single(p => p.Name == "version");
            Assert.Equal(typeof(long), version.ParameterType);
            Assert.False(version.HasDefaultValue, $"{name} must not be callable without the version it deletes");
        }

        await Client.Network.CreateProfileAsync(new CreateNetworkReplyProfileRequest
        {
            SegmentId = SegmentId, SegmentVersion = 11, Profile = new NetworkReplyProfileInput { SessionTimeoutSecs = 600 },
        });
        Assert.Equal(11, createProfile.Last.Json().GetProperty("segment_version").GetInt64());
        Assert.Equal(SegmentId.ToString(), createProfile.Last.Json().GetProperty("segment_id").GetString());

        await Client.Network.ReplaceProfileAsync(SegmentId, new ReplaceNetworkReplyProfileRequest
        {
            Version = 12, SegmentVersion = 13, Profile = new NetworkReplyProfileInput { SessionTimeoutSecs = 600 },
        });
        Assert.Equal(12, replaceProfile.Last.Json().GetProperty("version").GetInt64());
        Assert.Equal(13, replaceProfile.Last.Json().GetProperty("segment_version").GetInt64());

        await Client.Network.ReplacePolicyAsync(new ReplaceNetworkPolicyRequest { SessionTimeoutMaxSecs = 600, Version = 0 });
        Assert.Equal(0, replacePolicy.Last.Json().GetProperty("version").GetInt64());
    }

    /// <summary>A 409 to each write is a <see cref="ConflictError"/> after exactly one request, exposing the body's <c>reason_code</c>.</summary>
    [Fact]
    public async Task AConflictToEachWriteIsOneRequestAndExposesTheReasonCode()
    {
        const string stale = """{"error":"conflict","message":"the row changed since it was read","reason_code":"stale_version"}""";
        var writes = new (string Method, string Path, Func<Task> Call)[]
        {
            ("POST", Segments, () => Client.Network.CreateSegmentAsync(NewSegment())),
            ("PUT", $"{Segments}/{SegmentId}", () => Client.Network.ReplaceSegmentAsync(SegmentId, new ReplaceNetworkSegmentRequest { Version = 1, VlanId = 20, FilterIds = Array.Empty<string>(), Enabled = true })),
            ("DELETE", $"{Segments}/{SegmentId}", () => Client.Network.DeleteSegmentAsync(SegmentId, 1)),
            ("POST", Profiles, () => Client.Network.CreateProfileAsync(new CreateNetworkReplyProfileRequest { SegmentId = SegmentId, SegmentVersion = 1, Profile = new NetworkReplyProfileInput { SessionTimeoutSecs = 600 } })),
            ("PUT", $"{Profiles}/{SegmentId}", () => Client.Network.ReplaceProfileAsync(SegmentId, new ReplaceNetworkReplyProfileRequest { Version = 1, SegmentVersion = 1, Profile = new NetworkReplyProfileInput { SessionTimeoutSecs = 600 } })),
            ("DELETE", $"{Profiles}/{SegmentId}", () => Client.Network.DeleteProfileAsync(SegmentId, 1)),
            ("PUT", Policy, () => Client.Network.ReplacePolicyAsync(new ReplaceNetworkPolicyRequest { SessionTimeoutMaxSecs = 600, Version = 1 })),
        };

        foreach ((string method, string path, Func<Task> call) in writes)
        {
            Route route = Mount(method, path, 409, stale);
            ConflictError error = await Assert.ThrowsAsync<ConflictError>(call);
            Assert.Equal(1, route.Calls);
            Assert.Equal("stale_version", error.ReasonCode);
            Assert.IsAssignableFrom<AuthzError>(error);   // §27.9: catchable as AuthzError
        }

        // `already_exists` is the other slug, and maps the same way.
        Route create = Mount("POST", Segments, 409,
            """{"error":"already_exists","message":"that VLAN is taken","reason_code":"duplicate_vlan"}""");
        ConflictError duplicate = await Assert.ThrowsAsync<ConflictError>(() => Client.Network.CreateSegmentAsync(NewSegment()));
        Assert.Equal("duplicate_vlan", duplicate.ReasonCode);
        Assert.Equal(1, create.Calls);

        // The vocabulary is open: a value this SDK has never seen is surfaced verbatim; a server that sends none gives null.
        Mount("POST", Segments, 409, """{"error":"conflict","message":"m","reason_code":"a_future_reason"}""");
        Assert.Equal("a_future_reason", (await Assert.ThrowsAsync<ConflictError>(() => Client.Network.CreateSegmentAsync(NewSegment()))).ReasonCode);
        Mount("POST", Segments, 409, """{"error":"conflict","message":"m"}""");
        Assert.Null((await Assert.ThrowsAsync<ConflictError>(() => Client.Network.CreateSegmentAsync(NewSegment()))).ReasonCode);
    }

    // ------------------------------------------------------------------
    // §36.8 test 3 — closed bodies
    // ------------------------------------------------------------------

    /// <summary>The serialized requests carry exactly the keys &#167;36.2 names for the members set; an unset optional is absent, never null.</summary>
    [Fact]
    public async Task ClosedBodiesCarryExactlyTheKeysSetAndNeverNull()
    {
        Route createSegment = Mount("POST", Segments, 201, SegmentBody().ToJsonString());
        Route replaceSegment = Mount("PUT", $"{Segments}/{SegmentId}", 200, SegmentBody().ToJsonString());
        Route createProfile = Mount("POST", Profiles, 201, ProfileBody().ToJsonString());
        Route replacePolicy = Mount("PUT", Policy, 200, PolicyBody().ToJsonString());

        await Client.Network.CreateSegmentAsync(NewSegment());
        Assert.Equal(new[] { "kind", "name", "site_key", "vlan_id" }, createSegment.Last.Keys());
        Assert.Equal("access", createSegment.Last.Json().GetProperty("kind").GetString());   // the wire spelling

        await Client.Network.CreateSegmentAsync(NewSegment() with
        {
            Kind = NetworkSegmentKind.Quarantine, Rank = null, FilterIds = new[] { "q" }, Enabled = false,
        });
        Assert.Equal(new[] { "enabled", "filter_ids", "kind", "name", "site_key", "vlan_id" }, createSegment.Last.Keys());
        Assert.Equal("quarantine", createSegment.Last.Json().GetProperty("kind").GetString());

        await Client.Network.ReplaceSegmentAsync(SegmentId, new ReplaceNetworkSegmentRequest
        {
            Version = 1, VlanId = 20, FilterIds = Array.Empty<string>(), Enabled = true,
        });
        Assert.Equal(new[] { "enabled", "filter_ids", "version", "vlan_id" }, replaceSegment.Last.Keys());   // no kind, site_key, name; rank unset: absent

        await Client.Network.CreateProfileAsync(new CreateNetworkReplyProfileRequest
        {
            SegmentId = SegmentId, SegmentVersion = 4, Profile = new NetworkReplyProfileInput { SessionTimeoutSecs = 600 },
        });
        Assert.Equal(new[] { "profile", "segment_id", "segment_version" }, createProfile.Last.Keys());
        JsonElement profile = createProfile.Last.Json().GetProperty("profile");
        Assert.Equal(new[] { "session_timeout_secs" }, profile.EnumerateObject().Select(p => p.Name).ToArray());   // no idle, filter_id, service_type, vlan

        await Client.Network.ReplacePolicyAsync(new ReplaceNetworkPolicyRequest { SessionTimeoutMaxSecs = 600, Version = 0 });
        Assert.Equal(new[] { "session_timeout_max_secs", "version" }, replacePolicy.Last.Keys());

        // A NetworkReplyProfileInput has no VLAN member, and the replace types are not constructible without their required members.
        Assert.DoesNotContain(typeof(NetworkReplyProfileInput).GetProperties(), p => p.Name.Contains("Vlan", StringComparison.OrdinalIgnoreCase));
        foreach (Type replace in new[] { typeof(ReplaceNetworkSegmentRequest), typeof(ReplaceNetworkReplyProfileRequest), typeof(ReplaceNetworkPolicyRequest), typeof(CreateNetworkReplyProfileRequest) })
        {
            Assert.All(
                replace.GetProperties().Where(p => p.Name is "Version" or "SegmentVersion" or "SegmentId" or "Profile" or "VlanId" or "FilterIds" or "Enabled" or "SessionTimeoutMaxSecs"),
                p => Assert.True(
                    p.GetCustomAttributes(typeof(System.Runtime.CompilerServices.RequiredMemberAttribute), true).Length > 0,
                    $"{replace.Name}.{p.Name} must be a required member"));
        }
    }

    // ------------------------------------------------------------------
    // §36.8 test 4 — open decoding and pagination
    // ------------------------------------------------------------------

    /// <summary>Unknown enumeration values decode; a clamped profile decodes with both members.</summary>
    [Fact]
    public async Task UnknownEnumerationValuesDecodeAndAClampedProfileKeepsBothMembers()
    {
        Mount("GET", $"{Segments}/{SegmentId}", 200, SegmentBody(kind: "a_future_kind").ToJsonString());
        Assert.Equal(NetworkSegmentKind.Unknown, (await Client.Network.GetSegmentAsync(SegmentId)).Kind);

        Mount("GET", $"{Profiles}/{SegmentId}", 200,
            ProfileBody(termination: "a_future_action", service: "a_future_service", clamped: true, timeout: 900).ToJsonString());
        NetworkReplyProfile profile = await Client.Network.GetProfileAsync(SegmentId);
        Assert.Equal(RadiusTerminationAction.Unknown, profile.TerminationAction);
        Assert.Equal(RadiusServiceType.Unknown, profile.ServiceType);
        Assert.True(profile.SessionTimeoutClamped);
        Assert.Equal(900, profile.SessionTimeoutSecs);
    }

    /// <summary>Both lists return a page with a <c>total</c>, and the auto-pager carries <c>search</c> and <c>site</c> on every request.</summary>
    [Fact]
    public async Task BothListsPageAndTheAutoPagerCarriesSearchAndSiteOnEveryRequest()
    {
        Route segments = MountDynamic("GET", Segments, 200, r =>
        {
            int offset = int.Parse(r.Query["offset"], System.Globalization.CultureInfo.InvariantCulture);
            return $$"""{"items":[{{SegmentBody().ToJsonString()}}],"total":2,"offset":{{offset}},"limit":1}""";
        });
        Page<NetworkSegmentResponse> page = await Client.Network.ListSegmentsAsync("hq", PageRequest.Matching(1, "lab"));
        Assert.Equal(2, page.Total);
        Assert.Single(page.Items);

        IReadOnlyList<NetworkSegmentResponse> all =
            await Client.Network.ListSegmentsAllAsync("hq", PageRequest.Matching(1, "lab"));
        Assert.Equal(2, all.Count);
        Assert.All(segments.Requests.Skip(1), r =>
        {
            Assert.Equal("lab", r.Query["search"]);
            Assert.Equal("hq", r.Query["site"]);
        });

        Route profiles = MountDynamic("GET", Profiles, 200, r =>
        {
            int offset = int.Parse(r.Query["offset"], System.Globalization.CultureInfo.InvariantCulture);
            return $$"""{"items":[{{ProfileBody().ToJsonString()}}],"total":2,"offset":{{offset}},"limit":1}""";
        });
        Assert.Equal(2, (await Client.Network.ListProfilesAsync(PageRequest.Matching(1, "lab-in"))).Total);
        Assert.Equal(2, (await Client.Network.ListProfilesAllAsync(PageRequest.Matching(1, "lab-in"))).Count);
        Assert.All(profiles.Requests.Skip(1), r => Assert.Equal("lab-in", r.Query["search"]));
    }

    // ------------------------------------------------------------------
    // §36.8 test 5 — errors
    // ------------------------------------------------------------------

    /// <summary>403 carries <c>action</c> and <c>resource_id</c>; 400, 404, 401, 429 and 503 map as &#167;36.4 says.</summary>
    [Fact]
    public async Task ErrorsMapAsTheContractSays()
    {
        Mount("POST", Segments, 403,
            $$"""{"error":"authorization_denied","message":"missing network:grant","action":"network:grant","resource_id":"{{SegmentId}}"}""");
        AuthzError denied = await Assert.ThrowsAsync<AuthzError>(() => Client.Network.CreateSegmentAsync(NewSegment()));
        Assert.Equal("network:grant", denied.Action);
        Assert.Equal(SegmentId.ToString(), denied.ResourceId);

        Mount("POST", Segments, 400, """{"error":"validation_error","message":"vlan_id must be 1-4094"}""");
        ValidationError invalid = await Assert.ThrowsAsync<ValidationError>(() => Client.Network.CreateSegmentAsync(NewSegment()));
        Assert.Contains("vlan_id must be 1-4094", invalid.Message, StringComparison.Ordinal);

        Mount("GET", $"{Profiles}/{SegmentId}", 404, """{"error":"not_found","message":"no such profile"}""");
        await Assert.ThrowsAsync<NotFoundError>(() => Client.Network.GetProfileAsync(SegmentId));

        Mount("GET", Policy, 401, """{"error":"unauthorized","message":"service accounts are refused"}""");
        await Assert.ThrowsAsync<AuthError>(() => Client.Network.GetPolicyAsync());

        var writes = new (string Method, string Path, Func<Task> Call)[]
        {
            ("POST", Segments, () => Client.Network.CreateSegmentAsync(NewSegment())),
            ("PUT", $"{Segments}/{SegmentId}", () => Client.Network.ReplaceSegmentAsync(SegmentId, new ReplaceNetworkSegmentRequest { Version = 1, VlanId = 20, FilterIds = Array.Empty<string>(), Enabled = true })),
            ("DELETE", $"{Segments}/{SegmentId}", () => Client.Network.DeleteSegmentAsync(SegmentId, 1)),
            ("POST", Profiles, () => Client.Network.CreateProfileAsync(new CreateNetworkReplyProfileRequest { SegmentId = SegmentId, SegmentVersion = 1, Profile = new NetworkReplyProfileInput { SessionTimeoutSecs = 600 } })),
            ("PUT", $"{Profiles}/{SegmentId}", () => Client.Network.ReplaceProfileAsync(SegmentId, new ReplaceNetworkReplyProfileRequest { Version = 1, SegmentVersion = 1, Profile = new NetworkReplyProfileInput { SessionTimeoutSecs = 600 } })),
            ("DELETE", $"{Profiles}/{SegmentId}", () => Client.Network.DeleteProfileAsync(SegmentId, 1)),
            ("PUT", Policy, () => Client.Network.ReplacePolicyAsync(new ReplaceNetworkPolicyRequest { SessionTimeoutMaxSecs = 600, Version = 1 })),
        };
        foreach (int status in new[] { 429, 503 })
        {
            foreach ((string method, string path, Func<Task> call) in writes)
            {
                Route route = Mount(method, path, status, """{"error":"unavailable","message":"later"}""");
                await Assert.ThrowsAsync<NetworkError>(call);
                Assert.Equal(1, route.Calls);
            }
        }
    }

    /// <summary>A 403 for a value rule (H3) reaches the caller with the server's message and neither <c>action</c> nor <c>resource_id</c>.</summary>
    [Fact]
    public async Task ABodyOnlyForbiddenKeepsTheServersMessage()
    {
        Mount("PUT", $"{Profiles}/{SegmentId}", 403,
            """{"error":"authorization_denied","message":"session_timeout_secs is above the tenant's cap of 3600"}""");
        AuthzError error = await Assert.ThrowsAsync<AuthzError>(() => Client.Network.ReplaceProfileAsync(
            SegmentId,
            new ReplaceNetworkReplyProfileRequest { Version = 1, SegmentVersion = 1, Profile = new NetworkReplyProfileInput { SessionTimeoutSecs = 7200 } }));
        Assert.Contains("session_timeout_secs is above the tenant's cap of 3600", error.Message, StringComparison.Ordinal);
        Assert.Null(error.Action);
        Assert.Null(error.ResourceId);
    }

    // ------------------------------------------------------------------
    // §27.11 rule 5 — the request user_id is an untyped string; null is "none"
    // ------------------------------------------------------------------

    private static JsonObject CertBody() => new()
    {
        ["cert_type"] = "User", ["created_at"] = "2026-10-16T00:00:00Z", ["fingerprint"] = "example",
        ["id"] = Guid.NewGuid().ToString(), ["issuer_ca_id"] = ExampleId.ToString(), ["key_algorithm"] = "Rsa4096",
        ["metadata"] = new JsonObject(), ["not_after"] = "2027-10-16T00:00:00Z", ["not_before"] = "2026-10-16T00:00:00Z",
        ["public_cert_pem"] = "example", ["private_key_pem"] = "example", ["status"] = "Active", ["subject"] = "example",
        ["tenant_id"] = TenantId.ToString(),
    };

    /// <summary>The request <c>user_id</c> is a plain string: a value that is not a UUID is sent, and the server's 400 is surfaced.</summary>
    [Fact]
    public async Task TheRequestUserIdIsAnUntypedStringSoAMalformedValueReachesTheServer()
    {
        Assert.Equal(typeof(string), typeof(CreateCertificateRequest).GetProperty("UserId")!.PropertyType);
        Assert.Equal(typeof(string), typeof(SignCertificateCsrRequest).GetProperty("UserId")!.PropertyType);
        Assert.Equal(typeof(Guid?), typeof(Certificate).GetProperty("UserId")!.PropertyType);            // the response member stays typed
        Assert.Equal(typeof(Guid?), typeof(GeneratedCertificate).GetProperty("UserId")!.PropertyType);

        Route generate = Mount("POST", "/api/v1/certificates", 400, """{"error":"validation_error","message":"user_id is not a UUID"}""");
        ValidationError error = await Assert.ThrowsAsync<ValidationError>(() => Client.Certificates.GenerateAsync(new CreateCertificateRequest
        {
            CertType = CertificateType.User, IssuerCaId = ExampleId, KeyAlgorithm = KeyAlgorithm.Rsa4096,
            Subject = "example", ValidityDays = 365, UserId = "not-a-uuid",
        }));
        Assert.Contains("user_id is not a UUID", error.Message, StringComparison.Ordinal);
        Assert.Equal("not-a-uuid", generate.Last.Json().GetProperty("user_id").GetString());   // sent as given, never judged client-side

        Route sign = Mount("POST", "/api/v1/certificates/sign-csr", 400, """{"error":"validation_error","message":"user_id is not a UUID"}""");
        await Assert.ThrowsAsync<ValidationError>(() => Client.Certificates.SignCsrAsync(new SignCertificateCsrRequest
        {
            CertType = CertificateType.User, CsrPem = "example", IssuerCaId = ExampleId, ValidityDays = 365, UserId = "42",
        }));
        Assert.Equal("42", sign.Last.Json().GetProperty("user_id").GetString());
    }

    /// <summary>An explicitly assigned null on <c>user_id</c> is "none": the key is omitted, and null is never sent.</summary>
    [Fact]
    public async Task AnAssignedNullUserIdIsNoneAndNullIsNeverSent()
    {
        Route generate = Mount("POST", "/api/v1/certificates", 201, CertBody().ToJsonString());
        Route sign = Mount("POST", "/api/v1/certificates/sign-csr", 201, CertBody().ToJsonString());

        await Client.Certificates.GenerateAsync(new CreateCertificateRequest
        {
            CertType = CertificateType.User, IssuerCaId = ExampleId, KeyAlgorithm = KeyAlgorithm.Rsa4096,
            Subject = "example", ValidityDays = 365, UserId = null,
        });
        Assert.DoesNotContain("user_id", generate.Last.Keys());
        Assert.DoesNotContain("null", generate.Last.Body, StringComparison.Ordinal);

        await Client.Certificates.SignCsrAsync(new SignCertificateCsrRequest
        {
            CertType = CertificateType.User, CsrPem = "example", IssuerCaId = ExampleId, ValidityDays = 365, UserId = null,
        });
        Assert.DoesNotContain("user_id", sign.Last.Keys());
        Assert.DoesNotContain("null", sign.Last.Body, StringComparison.Ordinal);
    }

    /// <summary>The same rule for <c>expected_updated_at</c> on <c>scim_targets.update</c> (string, null is none).</summary>
    [Fact]
    public void ExpectedUpdatedAtIsAStringOnBothUpdatesAndNullIsOmitted()
    {
        Assert.Equal(typeof(string), typeof(SsfStreamInput).GetProperty("ExpectedUpdatedAt")!.PropertyType);
        Assert.Equal(typeof(string), typeof(ScimTargetInput).GetProperty("ExpectedUpdatedAt")!.PropertyType);
        foreach (string json in new[]
                 {
                     ManagementSupport.EncodeBody("ssf.update_stream", new SsfStreamInput
                     {
                         ReceiverClientId = "r", Audience = "a", DeliveryMethod = SsfDeliveryMethod.Poll,
                         EventsAllowed = new[] { SsfEventType.SessionRevoked }, ExpectedUpdatedAt = null,
                     }),
                     ManagementSupport.EncodeBody("scim_targets.update", new ScimTargetInput
                     {
                         Auth = new ScimTargetAuthBearer(), BaseUrl = "https://scim.example", Name = "n",
                         Scope = new ScimTargetScopeAllUsers(), ExpectedUpdatedAt = null,
                     }),
                 })
        {
            Assert.DoesNotContain("expected_updated_at", json, StringComparison.Ordinal);
            Assert.DoesNotContain("null", json, StringComparison.Ordinal);
        }
    }
}
