using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Management.Models;
using Axiam.Sdk.Ssf;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests.Management;

/// <summary>The <c>ssf</c> management namespace — CONTRACT.md &#167;32.8's six management tests.</summary>
public sealed class SsfManagementTests : ManagementTestBase
{
    private static string Streams => $"/api/v1/tenants/{TenantId}/ssf/streams";

    private static JsonObject StreamBody(Action<JsonObject>? edit = null)
    {
        var body = JsonNode.Parse(
            $$"""
              {"id":"{{Guid.NewGuid()}}","tenant_id":"{{TenantId}}","receiver_client_id":"rp-client",
               "audience":"https://rp.example","description":null,"delivery_method":"push",
               "endpoint_url":"https://rp.example/ssf/push","authorization_header_set":true,
               "events_allowed":["{{SsfEventTypes.SessionRevoked}}","{{SsfEventTypes.AccountDisabled}}"],
               "events_requested":["{{SsfEventTypes.SessionRevoked}}"],
               "events_delivered":["{{SsfEventTypes.SessionRevoked}}"],
               "subject_format":"iss_sub","status":"enabled","status_reason":null,"status_actor":"admin",
               "last_verification_at":null,"created_at":"2026-10-04T00:00:00Z","updated_at":"2026-10-04T00:00:00Z",
               "transmitter_active":true}
              """)!.AsObject();
        edit?.Invoke(body);
        return body;
    }

    private static SsfStreamInput Input(string? header) => new()
    {
        ReceiverClientId = "rp-client",
        Audience = "https://rp.example",
        DeliveryMethod = SsfDeliveryMethod.Push,
        EventsAllowed = new[] { SsfEventType.SessionRevoked, SsfEventType.AccountDisabled },
        EndpointUrl = "https://rp.example/ssf/push",
        AuthorizationHeader = header is null ? null : Sensitive<string>.Wrap(header),
    };

    /// <summary>&#167;32.8 (1): update_stream PUTs every member it models; the input needs its four required members.</summary>
    [Fact]
    public async Task UpdateStreamPutsEveryMemberItModels()
    {
        Guid id = Guid.NewGuid();
        Route put = Mount("PUT", $"{Streams}/{id}", 200, StreamBody().ToJsonString());
        SsfStream updated = await Client.Ssf.UpdateStreamAsync(id, Input(null) with
        {
            Description = "SIEM",
            EventsRequested = new[] { SsfEventType.SessionRevoked },
            SubjectFormat = SsfSubjectFormat.Email,
            Status = SsfStreamStatus.Paused,
            StatusReason = "maintenance",
            ClearAuthorizationHeader = false,
        });

        Assert.Equal("PUT", put.Last.Method);
        Assert.Equal(
            new[]
            {
                "audience", "clear_authorization_header", "delivery_method", "description", "endpoint_url",
                "events_allowed", "events_requested", "receiver_client_id", "status", "status_reason", "subject_format",
            },
            put.Last.Keys());
        Assert.Equal(SsfEventTypes.AccountDisabled, put.Last.Json().GetProperty("events_allowed")[1].GetString());
        Assert.Equal(SsfDeliveryMethod.Push, updated.DeliveryMethod);
        foreach (string name in new[] { "ReceiverClientId", "Audience", "DeliveryMethod", "EventsAllowed" })
        {
            Assert.NotNull(typeof(SsfStreamInput).GetProperty(name)!
                .GetCustomAttribute<System.Runtime.CompilerServices.RequiredMemberAttribute>());
        }
    }

    /// <summary>&#167;32.8 (2): the header is sent, never rendered, and never decoded from a response.</summary>
    [Fact]
    public async Task ThePushHeaderIsSentAndNeverRenderedOrDecoded()
    {
        string header = $"Bearer {Secrets.Fresh()}";
        string secret = header["Bearer ".Length..];
        SsfStreamInput input = Input(header);
        Secrets.AssertAbsent(input.ToString(), secret, "ToString");
        Secrets.AssertAbsent(JsonSerializer.Serialize(input), secret, "Json");

        Route create = Mount("POST", Streams, 201, StreamBody(b => b["authorization_header"] = header).ToJsonString());
        SsfStream stream = await Client.Ssf.CreateStreamAsync(input);
        Assert.Equal(header, create.Last.Json().GetProperty("authorization_header").GetString());
        Secrets.AssertAbsent(stream.ToString(), secret, "response ToString");
        Secrets.AssertAbsent(JsonSerializer.Serialize(stream), secret, "response Json");
        Assert.Null(typeof(SsfStream).GetProperty("AuthorizationHeader"));
        Assert.True(stream.AuthorizationHeaderSet);
    }

    /// <summary>&#167;32.8 (3): unknown values and both transmitter states decode.</summary>
    [Fact]
    public async Task UnknownValuesAndBothTransmitterStatesDecode()
    {
        Guid odd = Guid.NewGuid();
        Guid inactive = Guid.NewGuid();
        Guid active = Guid.NewGuid();
        Mount("GET", $"{Streams}/{odd}", 200, StreamBody(b =>
        {
            b["status"] = "quarantined";
            b["delivery_method"] = "websocket";
            b["subject_format"] = "phone_number";
            b["status_actor"] = "policy";
            b["events_allowed"] = new JsonArray("https://schemas.openid.net/secevent/caep/event-type/token-claims-change");
        }).ToJsonString());
        Mount("GET", $"{Streams}/{inactive}", 200, StreamBody(b =>
        {
            b["transmitter_active"] = false;
            b["transmitter_inactive_reason"] = "the shared-issuer gate holds";
        }).ToJsonString());
        Mount("GET", $"{Streams}/{active}", 200, StreamBody(b => b["transmitter_active"] = false).ToJsonString());

        SsfStream s = await Client.Ssf.GetStreamAsync(odd);
        Assert.Equal(SsfStreamStatus.Unknown, s.Status);
        Assert.Equal(SsfDeliveryMethod.Unknown, s.DeliveryMethod);
        Assert.Equal(SsfSubjectFormat.Unknown, s.SubjectFormat);
        Assert.Equal(SsfStatusActor.Unknown, s.StatusActor);
        Assert.Equal(SsfEventType.Unknown, s.EventsAllowed[0]);
        SsfStream gated = await Client.Ssf.GetStreamAsync(inactive);
        Assert.False(gated.TransmitterActive);
        Assert.Equal("the shared-issuer gate holds", gated.TransmitterInactiveReason);
        SsfStream noReason = await Client.Ssf.GetStreamAsync(active);
        Assert.Null(noReason.TransmitterInactiveReason);
    }

    /// <summary>&#167;32.8 (4): list_streams pages and the walk carries search.</summary>
    [Fact]
    public async Task ListStreamsPagesAndTheWalkCarriesSearch()
    {
        Route list = MountDynamic("GET", Streams, 200, recorded =>
        {
            int offset = int.Parse(recorded.Query["offset"], System.Globalization.CultureInfo.InvariantCulture);
            string items = offset < 2 ? $"[{StreamBody().ToJsonString()}]" : "[]";
            return $$"""{"items":{{items}},"total":2,"offset":{{offset}},"limit":1}""";
        });
        Page<SsfStream> page = await Client.Ssf.ListStreamsAsync(PageRequest.Matching(1, "rp"));
        Assert.Equal(2, page.Total);
        IReadOnlyList<SsfStream> all = await Client.Ssf.ListStreamsAllAsync(PageRequest.Matching(1, "rp"));
        Assert.Equal(2, all.Count);
        Assert.All(list.Requests, r => Assert.Equal("rp", r.Query["search"]));
    }

    /// <summary>&#167;32.8 (5): none of the three writes is retried on a 503.</summary>
    [Fact]
    public async Task NoneOfTheThreeWritesIsRetriedOn503()
    {
        Guid id = Guid.NewGuid();
        Route[] routes =
        {
            Mount("POST", Streams, 503, string.Empty),
            Mount("PUT", $"{Streams}/{id}", 503, string.Empty),
            Mount("DELETE", $"{Streams}/{id}", 503, string.Empty),
        };
        await Assert.ThrowsAsync<NetworkError>(() => Client.Ssf.CreateStreamAsync(Input(null)));
        await Assert.ThrowsAsync<NetworkError>(() => Client.Ssf.UpdateStreamAsync(id, Input(null)));
        await Assert.ThrowsAsync<NetworkError>(() => Client.Ssf.DeleteStreamAsync(id));
        Assert.All(routes, r => Assert.Equal(1, r.Calls));
    }

    /// <summary>&#167;32.8 (6): the status mapping.</summary>
    [Fact]
    public async Task StatusesMapPerSection2()
    {
        Guid id = Guid.NewGuid();
        Mount("PUT", $"{Streams}/{id}", 400, """{"error":"validation_error","message":"endpoint_url: must be https"}""");
        Mount("POST", Streams, 409, """{"error":"conflict","message":"audience"}""");
        Mount("GET", $"{Streams}/{id}", 404, """{"error":"not_found","message":"no"}""");
        Mount("DELETE", $"{Streams}/{id}", 401, """{"error":"unauthorized"}""");

        ValidationError v = await Assert.ThrowsAsync<ValidationError>(() => Client.Ssf.UpdateStreamAsync(id, Input(null)));
        Assert.Contains("must be https", v.Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<ConflictError>(() => Client.Ssf.CreateStreamAsync(Input(null)));
        await Assert.ThrowsAsync<NotFoundError>(() => Client.Ssf.GetStreamAsync(id));
        await Assert.ThrowsAsync<AuthError>(() => Client.Ssf.DeleteStreamAsync(id));
    }

    /// <summary>A read converts into the replacement body without the header.</summary>
    [Fact]
    public void AReadConvertsIntoTheReplacementBodyWithoutTheHeader()
    {
        SsfStream stream = ManagementSupport.Decode<SsfStream>("test", JsonDocument.Parse(StreamBody().ToJsonString()).RootElement);
        SsfStreamInput body = stream.ToInput();
        Assert.Null(body.AuthorizationHeader);
        Assert.Null(body.ClearAuthorizationHeader);
        Assert.Equal(stream.EndpointUrl, body.EndpointUrl);
        Assert.Equal(new[] { SsfEventType.SessionRevoked }, body.EventsRequested);
    }
}
