using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Ssf;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>
/// CONTRACT.md contract 1.61: <c>Certificate.user_id</c> and its two request members
/// (&#167;27.11 rule 5, its required test), and <c>SsfStreamInput.expected_updated_at</c> with the
/// three meanings of <c>events_requested</c> on an update (&#167;32.2, &#167;32.3 rule 4, &#167;32.8 test 1).
/// <c>CibaPendingList</c> (&#167;33.3 rule 16) is not modelled by this SDK: no registry operation
/// returns it and the generator emits only the models its operations carry.
/// </summary>
public sealed class Contract161ModelsTests : ManagementTestBase
{
    private static string Streams => $"/api/v1/tenants/{TenantId}/ssf/streams";

    private static JsonObject CertBody(Guid? userId, bool withMember = true, Action<JsonObject>? edit = null)
    {
        var body = new JsonObject
        {
            ["cert_type"] = "User",
            ["created_at"] = "2026-10-13T00:00:00Z",
            ["fingerprint"] = "example",
            ["id"] = Guid.NewGuid().ToString(),
            ["issuer_ca_id"] = ExampleId.ToString(),
            ["key_algorithm"] = "Rsa4096",
            ["metadata"] = new JsonObject(),
            ["not_after"] = "2027-10-13T00:00:00Z",
            ["not_before"] = "2026-10-13T00:00:00Z",
            ["public_cert_pem"] = "example",
            ["status"] = "Active",
            ["subject"] = "example",
            ["tenant_id"] = TenantId.ToString(),
        };
        if (withMember)
        {
            body["user_id"] = userId?.ToString();
        }

        edit?.Invoke(body);
        return body;
    }

    private static CreateCertificateRequest GenerateRequest(Guid? userId) => new()
    {
        CertType = CertificateType.User,
        IssuerCaId = ExampleId,
        KeyAlgorithm = KeyAlgorithm.Rsa4096,
        Subject = "example",
        ValidityDays = 365,
        UserId = userId,
    };

    private static SignCertificateCsrRequest SignRequest(Guid? userId) => new()
    {
        CertType = CertificateType.User,
        CsrPem = "example",
        IssuerCaId = ExampleId,
        ValidityDays = 365,
        UserId = userId,
    };

    /// <summary>&#167;27.11 rule 5's required test, request side: sent exactly as given, no key without one.</summary>
    [Fact]
    public async Task GenerateAndSignCsrSendUserIdExactlyAsGivenAndNoKeyWithoutOne()
    {
        Guid user = Guid.NewGuid();
        Route generate = Mount("POST", "/api/v1/certificates", 201,
            CertBody(user, edit: b => b["private_key_pem"] = "example").ToJsonString());
        Route sign = Mount("POST", "/api/v1/certificates/sign-csr", 201, CertBody(user).ToJsonString());

        await Client.Certificates.GenerateAsync(GenerateRequest(user));
        Assert.Equal(user.ToString(), generate.Last.Json().GetProperty("user_id").GetString());
        await Client.Certificates.GenerateAsync(GenerateRequest(null));
        Assert.False(generate.Last.Json().TryGetProperty("user_id", out _), "no account named: no key, and never null");

        await Client.Certificates.SignCsrAsync(SignRequest(user));
        Assert.Equal(user.ToString(), sign.Last.Json().GetProperty("user_id").GetString());
        await Client.Certificates.SignCsrAsync(SignRequest(null));
        Assert.False(sign.Last.Json().TryGetProperty("user_id", out _), "no account named: no key, and never null");
    }

    /// <summary>&#167;27.11 rule 5's required test, response side: a UUID, a null and no member all decode.</summary>
    [Fact]
    public async Task ACertificateBodyWithAUuidANullAndNoMemberAllDecode()
    {
        Guid user = Guid.NewGuid();
        JsonObject withUuid = CertBody(user);
        JsonObject withNull = CertBody(null);
        JsonObject without = CertBody(null, withMember: false);
        Mount("GET", $"/api/v1/certificates/{withUuid["id"]}", 200, withUuid.ToJsonString());
        Mount("GET", $"/api/v1/certificates/{withNull["id"]}", 200, withNull.ToJsonString());
        Mount("GET", $"/api/v1/certificates/{without["id"]}", 200, without.ToJsonString());

        Assert.Equal(user, (await Client.Certificates.GetAsync(Guid.Parse((string)withUuid["id"]!))).UserId);
        Assert.Null((await Client.Certificates.GetAsync(Guid.Parse((string)withNull["id"]!))).UserId);
        Assert.Null((await Client.Certificates.GetAsync(Guid.Parse((string)without["id"]!))).UserId);

        // Inside GeneratedCertificate: the same member, the same rule.
        JsonObject generated = CertBody(user, edit: b => b["private_key_pem"] = "example");
        Assert.Equal(user, JsonSerializer.Deserialize<GeneratedCertificate>(generated.ToJsonString(), ManagementJson.Reader)!.UserId);
        JsonObject generatedWithout = CertBody(null, withMember: false, edit: b => b["private_key_pem"] = "example");
        Assert.Null(JsonSerializer.Deserialize<GeneratedCertificate>(generatedWithout.ToJsonString(), ManagementJson.Reader)!.UserId);

        // Never synthesised from the metadata or the subject.
        JsonObject legacy = CertBody(null, withMember: false, edit: b => b["metadata"] = new JsonObject { ["user_id"] = user.ToString() });
        Assert.Null(JsonSerializer.Deserialize<Certificate>(legacy.ToJsonString(), ManagementJson.Reader)!.UserId);
    }

    private static JsonObject StreamBody(string version = "2026-10-04T00:00:00Z", JsonArray? requested = null) => new()
    {
        ["id"] = Guid.NewGuid().ToString(),
        ["tenant_id"] = TenantId.ToString(),
        ["receiver_client_id"] = "rp-client",
        ["audience"] = "https://rp.example",
        ["description"] = null,
        ["delivery_method"] = "push",
        ["endpoint_url"] = "https://rp.example/ssf/push",
        ["authorization_header_set"] = false,
        ["events_allowed"] = new JsonArray(SsfEventTypes.SessionRevoked, SsfEventTypes.AccountDisabled),
        ["events_requested"] = requested ?? new JsonArray(SsfEventTypes.SessionRevoked),
        ["events_delivered"] = new JsonArray(),
        ["subject_format"] = "iss_sub",
        ["status"] = "enabled",
        ["status_reason"] = null,
        ["status_actor"] = "admin",
        ["last_verification_at"] = null,
        ["created_at"] = "2026-10-04T00:00:00Z",
        ["updated_at"] = version,
        ["transmitter_active"] = true,
    };

    private static SsfStreamInput Input() => new()
    {
        ReceiverClientId = "rp-client",
        Audience = "https://rp.example",
        DeliveryMethod = SsfDeliveryMethod.Push,
        EventsAllowed = new[] { SsfEventType.SessionRevoked, SsfEventType.AccountDisabled },
        EndpointUrl = "https://rp.example/ssf/push",
    };

    /// <summary>&#167;32.8 (1), contract 1.61: <c>expected_updated_at</c> as given; <c>[]</c> as <c>[]</c>; unset absent.</summary>
    [Fact]
    public async Task ExpectedUpdatedAtIsSentExactlyAsGivenAndEventsRequestedKeepsItsThreeMeanings()
    {
        Guid id = Guid.NewGuid();
        Route put = Mount("PUT", $"{Streams}/{id}", 200, StreamBody().ToJsonString());

        // A non-UTC offset, a trailing-zero fraction and nanoseconds a DateTimeOffset would lose.
        foreach (string version in new[] { "2026-10-05T02:00:00.120000+02:00", "2026-10-05T01:02:03.123456789Z" })
        {
            await Client.Ssf.UpdateStreamAsync(id, Input() with { ExpectedUpdatedAt = version });
            Assert.Equal(version, put.Last.Json().GetProperty("expected_updated_at").GetString());
        }

        await Client.Ssf.UpdateStreamAsync(id, Input());
        Assert.False(put.Last.Json().TryGetProperty("expected_updated_at", out _), "absent when unset, never null");
        Assert.False(put.Last.Json().TryGetProperty("events_requested", out _), "unset: absent (resets to all of events_allowed)");

        await Client.Ssf.UpdateStreamAsync(id, Input() with { EventsRequested = Array.Empty<SsfEventType>() });
        JsonElement empty = put.Last.Json().GetProperty("events_requested");
        Assert.Equal(JsonValueKind.Array, empty.ValueKind);
        Assert.Equal(0, empty.GetArrayLength());

        await Client.Ssf.UpdateStreamAsync(id, Input() with { EventsRequested = new[] { SsfEventType.SessionRevoked } });
        Assert.Equal(SsfEventTypes.SessionRevoked, put.Last.Json().GetProperty("events_requested")[0].GetString());
    }

    /// <summary>&#167;32.3 rule 4: a <c>409</c> on update is surfaced after one request.</summary>
    [Fact]
    public async Task AConflictOnUpdateIsSurfacedAndNotRetried()
    {
        Guid id = Guid.NewGuid();
        Route conflict = Mount("PUT", $"{Streams}/{id}", 409,
            """{"error":"conflict","message":"the stream changed since it was read"}""");
        await Assert.ThrowsAsync<ConflictError>(() =>
            Client.Ssf.UpdateStreamAsync(id, Input() with { ExpectedUpdatedAt = "2026-10-04T00:00:00Z" }));
        Assert.Equal(1, conflict.Calls);
        Assert.Equal("2026-10-04T00:00:00Z", conflict.Last.Json().GetProperty("expected_updated_at").GetString());
    }

    /// <summary>&#167;32.2: the read-modify-write form sends back the <c>events_requested</c> and <c>updated_at</c> it read.</summary>
    [Fact]
    public async Task TheReadModifyWriteFormSendsBackWhatItRead()
    {
        const string version = "2026-10-05T01:02:03.123456789Z";
        Guid read = Guid.NewGuid();
        // The receiver narrowed the stream to "none": [] goes back as [], never omitted.
        Mount("GET", $"{Streams}/{read}", 200, StreamBody(version, new JsonArray()).ToJsonString());
        Route write = Mount("PUT", $"{Streams}/{read}", 200, StreamBody().ToJsonString());

        SsfStream stream = await Client.Ssf.GetStreamAsync(read);
        Assert.Empty(stream.EventsRequested);
        await Client.Ssf.UpdateStreamAsync(read, stream.ToInput() with { Description = "renamed" });
        JsonElement sent = write.Last.Json();
        Assert.Equal(JsonValueKind.Array, sent.GetProperty("events_requested").ValueKind);
        Assert.Equal(0, sent.GetProperty("events_requested").GetArrayLength());
        Assert.Equal(version, sent.GetProperty("expected_updated_at").GetString());
        Assert.Equal(version, (stream with { Description = "copied" }).ToInput().ExpectedUpdatedAt);

        // A stream the SDK did not decode itself carries its UpdatedAt in the round-trip format.
        SsfStream built = JsonSerializer.Deserialize<SsfStream>(StreamBody().ToJsonString(), ManagementJson.Reader)!;
        Assert.Equal("2026-10-04T00:00:00.0000000+00:00", built.ToInput().ExpectedUpdatedAt);
        Assert.Equal(built.EventsRequested.Count, built.ToInput().EventsRequested!.Count);
    }
}
