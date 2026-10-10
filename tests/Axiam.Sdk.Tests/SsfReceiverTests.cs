using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Options;
using Axiam.Sdk.Ssf;
using Axiam.Sdk.Tests.Fixtures;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// The &#167;32.7 SSF receiver helper — CONTRACT.md &#167;32.8's eight helper tests, with an
/// Ed25519 key generated at run time and SETs signed by the test.
/// </summary>
public sealed class SsfReceiverTests : IDisposable
{
    private static readonly Uri Base = new("https://axiam.test");
    private const string Issuer = "https://axiam.test/t/7c1e";
    private const string Audience = "https://rp.example";
    private const string JwksPath = "/oauth2/jwks";
    private const string StreamId = "3f0b9b1e-0d1c-4c2b-9a51-5c1d1d0f8a01";

    private readonly CapturingHandler _handler = new();
    private readonly AxiamClient _client;
    private readonly SigningKey _key = new();
    private readonly ManualClock _clock = new();

    public SsfReceiverTests()
    {
        _client = AxiamClient.CreateForTesting(
            Base, OidcTestKit.TenantGuid, new AxiamClientOptions { BaseUrl = Base, TenantId = OidcTestKit.TenantGuid }, _handler);
        _handler.Map("GET", JwksPath, _ => CapturingHandler.Json(200, Jwks(_key)));
    }

    public void Dispose() => _client.Dispose();

    private SsfReceiver Receiver(Func<CancellationToken, Task<Sensitive<string>>>? tokens = null) => new(_client, new SsfReceiverOptions
    {
        Issuer = Issuer,
        Audience = Audience,
        Keys = SsfKeySource.FromJwksUri($"https://axiam.test{JwksPath}"),
        AccessTokenProvider = tokens,
        TimeProvider = _clock,
    });

    private static JsonObject Claims(Action<JsonObject>? edit = null)
    {
        var claims = new JsonObject
        {
            ["iss"] = Issuer,
            ["aud"] = Audience,
            ["iat"] = 1_760_000_000,
            ["jti"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
            ["txn"] = "txn-1",
            ["sub_id"] = new JsonObject { ["format"] = "iss_sub", ["iss"] = Issuer, ["sub"] = Guid.NewGuid().ToString() },
            ["events"] = new JsonObject
            {
                [SsfEventTypes.SessionRevoked] = new JsonObject { ["event_timestamp"] = 1_760_000_000, ["initiating_entity"] = "admin" },
            },
        };
        edit?.Invoke(claims);
        return claims;
    }

    private static string Set(SigningKey key, JsonObject claims, string? typ = "secevent+jwt", string alg = "EdDSA", string? kid = null)
    {
        var header = new JsonObject { ["alg"] = alg, ["kid"] = kid ?? key.Kid };
        if (typ is not null)
        {
            header["typ"] = typ;
        }

        string signingInput = $"{B64(Encoding.UTF8.GetBytes(header.ToJsonString()))}.{B64(Encoding.UTF8.GetBytes(claims.ToJsonString()))}";
        return $"{signingInput}.{B64(key.Sign(Encoding.ASCII.GetBytes(signingInput)))}";
    }

    private static string Jwks(params SigningKey[] keys) => new JsonObject
    {
        ["keys"] = new JsonArray(keys.Select(k => (JsonNode?)new JsonObject
        {
            ["kty"] = "OKP", ["crv"] = "Ed25519", ["kid"] = k.Kid, ["x"] = B64(k.Public), ["alg"] = "EdDSA",
        }).ToArray()),
    }.ToJsonString();

    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static async Task<SetFailureReason> Refused(SsfReceiver receiver, string set) =>
        (await Assert.ThrowsAsync<SetVerificationError>(() => receiver.VerifySetAsync(set))).FailureReason;

    /// <summary>&#167;32.8 helper (1): a SET signed by the JWKS key verifies, every field the claim's; array aud and the long typ too.</summary>
    [Fact]
    public async Task AValidSetVerifiesWithEveryField()
    {
        SsfReceiver receiver = Receiver();
        JsonObject claims = Claims();
        SecurityEvent e = await receiver.VerifySetAsync(Set(_key, claims));
        Assert.Equal(claims["jti"]!.GetValue<string>(), e.Jti);
        Assert.Equal(1_760_000_000, e.Iat);
        Assert.Equal(Issuer, e.Iss);
        Assert.Equal(Audience, e.Aud.GetString());
        Assert.Equal("txn-1", e.Txn);
        Assert.Equal(SsfEventTypes.SessionRevoked, e.EventType);
        Assert.Equal("admin", e.Event.GetProperty("initiating_entity").GetString());
        Assert.Equal("iss_sub", e.SubId.GetProperty("format").GetString());

        SecurityEvent array = await receiver.VerifySetAsync(Set(_key, Claims(c =>
        {
            c["aud"] = new JsonArray("https://other.example", Audience);
            c.Remove("txn");
        }), typ: "APPLICATION/SECEVENT+JWT"));
        Assert.Equal(JsonValueKind.Array, array.Aud.ValueKind);
        Assert.Null(array.Txn);
    }

    /// <summary>&#167;32.8 helper (2): typ absent or JWT → invalid_type; alg none or HS256 → invalid_key; garbage → malformed.</summary>
    [Fact]
    public async Task TypeAndAlgorithmAreChecked()
    {
        SsfReceiver receiver = Receiver();
        Assert.Equal(SetFailureReason.InvalidType, await Refused(receiver, Set(_key, Claims(), typ: null)));
        Assert.Equal(SetFailureReason.InvalidType, await Refused(receiver, Set(_key, Claims(), typ: "JWT")));
        Assert.Equal(SetFailureReason.InvalidKey, await Refused(receiver, Set(_key, Claims(), alg: "none")));
        Assert.Equal(SetFailureReason.InvalidKey, await Refused(receiver, Set(_key, Claims(), alg: "HS256")));
        Assert.Equal(SetFailureReason.Malformed, await Refused(receiver, "a.b"));
        Assert.Equal(SetFailureReason.Malformed, await Refused(receiver, $"{B64(Encoding.UTF8.GetBytes("[1]"))}.{B64(Encoding.UTF8.GetBytes("{}"))}.{B64(new byte[] { 1 })}"));
        Assert.Equal(SetFailureReason.Malformed, await Refused(receiver, "!!.??.**"));
        Assert.Empty(_handler.To(JwksPath));
    }

    /// <summary>&#167;32.8 helper (3): another key with the same kid, and a tampered payload → invalid_key.</summary>
    [Fact]
    public async Task ASignatureByAnotherKeyOrATamperedPayloadIsInvalidKey()
    {
        SsfReceiver receiver = Receiver();
        var impostor = new SigningKey();
        Assert.Equal(SetFailureReason.InvalidKey, await Refused(receiver, Set(impostor, Claims(), kid: _key.Kid)));

        string[] parts = Set(_key, Claims()).Split('.');
        string tampered = B64(Encoding.UTF8.GetBytes(Claims(c => c["txn"] = "forged").ToJsonString()));
        Assert.Equal(SetFailureReason.InvalidKey, await Refused(receiver, $"{parts[0]}.{tampered}.{parts[2]}"));
        // A key the configured JWKS does not hold is never used, whatever kid the SET names.
        Assert.Equal(SetFailureReason.InvalidKey, await Refused(receiver, Set(impostor, Claims())));
    }

    /// <summary>&#167;32.8 helper (4): another iss → invalid_issuer; another aud → invalid_audience.</summary>
    [Fact]
    public async Task IssuerAndAudienceAreChecked()
    {
        SsfReceiver receiver = Receiver();
        Assert.Equal(SetFailureReason.InvalidIssuer, await Refused(receiver, Set(_key, Claims(c => c["iss"] = "https://evil.example"))));
        Assert.Equal(SetFailureReason.InvalidAudience, await Refused(receiver, Set(_key, Claims(c => c["aud"] = "https://other.example"))));
        Assert.Equal(SetFailureReason.InvalidAudience, await Refused(receiver, Set(_key, Claims(c => c["aud"] = new JsonArray("x")))));
    }

    /// <summary>&#167;32.8 helper (5): exp, sub, two events, no jti, no iat, no sub_id → invalid_request.</summary>
    [Fact]
    public async Task TheSetClaimRulesAreInvalidRequest()
    {
        SsfReceiver receiver = Receiver();
        Action<JsonObject>[] edits =
        {
            c => c["exp"] = 1_760_000_600,
            c => c["sub"] = "someone",
            c => c["events"]![SsfEventTypes.AccountDisabled] = new JsonObject(),
            c => c.Remove("jti"),
            c => c["jti"] = string.Empty,
            c => c.Remove("iat"),
            c => c["iat"] = "1760000000",
            c => c.Remove("sub_id"),
            c => c["events"] = new JsonObject(),
        };
        foreach (Action<JsonObject> edit in edits)
        {
            Assert.Equal(SetFailureReason.InvalidRequest, await Refused(receiver, Set(_key, Claims(edit))));
        }
    }

    /// <summary>&#167;32.8 helper (6): the same SET twice → replayed; a window under seven days is refused at configuration.</summary>
    [Fact]
    public async Task ASecondSightingIsReplayedAndAShortWindowIsRefused()
    {
        SsfReceiver receiver = Receiver();
        string set = Set(_key, Claims());
        await receiver.VerifySetAsync(set);
        SetVerificationError e = await Assert.ThrowsAsync<SetVerificationError>(() => receiver.VerifySetAsync(set));
        Assert.Equal(SetFailureReason.Replayed, e.FailureReason);
        Assert.Equal("replayed", e.Reason);
        Assert.Equal("invalid_request", SetErr.FromReason(e.FailureReason).Err);

        Assert.Throws<ValidationError>(() => new SsfReceiver(_client, new SsfReceiverOptions
        {
            Issuer = Issuer,
            Audience = Audience,
            Keys = SsfKeySource.FromJwksUri($"https://axiam.test{JwksPath}"),
            ReplayWindow = TimeSpan.FromDays(7) - TimeSpan.FromSeconds(1),
        }));
        Assert.Throws<ValidationError>(() => new SsfReceiver(_client, new SsfReceiverOptions
        {
            Issuer = string.Empty,
            Audience = Audience,
            Keys = SsfKeySource.FromJwksUri($"https://axiam.test{JwksPath}"),
        }));
    }

    /// <summary>&#167;32.8 helper (7): an unknown kid costs exactly one refetch; a second within the minute none.</summary>
    [Fact]
    public async Task AnUnknownKidCostsOneRefetchAtMostOnceAMinute()
    {
        SsfReceiver receiver = Receiver();
        await receiver.VerifySetAsync(Set(_key, Claims()));
        Assert.Single(_handler.To(JwksPath));

        var stranger = new SigningKey();
        Assert.Equal(SetFailureReason.InvalidKey, await Refused(receiver, Set(stranger, Claims())));
        Assert.Equal(2, _handler.To(JwksPath).Count);
        Assert.Equal(SetFailureReason.InvalidKey, await Refused(receiver, Set(new SigningKey(), Claims())));
        Assert.Equal(2, _handler.To(JwksPath).Count);

        // A minute later a rotated key is picked up by the one refetch it earns.
        _clock.Advance(TimeSpan.FromSeconds(61));
        _handler.Map("GET", JwksPath, _ => CapturingHandler.Json(200, Jwks(_key, stranger)));
        await receiver.VerifySetAsync(Set(stranger, Claims()));
        Assert.Equal(3, _handler.To(JwksPath).Count);
    }

    /// <summary>
    /// &#167;32.8 helper (8): poll sends ack and setErrs exactly as given, returns verified and
    /// refused apart, acknowledges nothing; a second poll with no options sends <c>{}</c>.
    /// </summary>
    [Fact]
    public async Task PollPassesAckAndSetErrsThroughAndSortsTheSets()
    {
        string pollToken = Secrets.Fresh();
        SsfReceiver receiver = Receiver(_ => Task.FromResult(Sensitive<string>.Wrap(pollToken)));
        JsonObject good = Claims();
        string goodJti = good["jti"]!.GetValue<string>();
        JsonObject mismatched = Claims();
        string badIssuerJti = Guid.NewGuid().ToString("N");
        var sets = new JsonObject
        {
            [goodJti] = Set(_key, good),
            [badIssuerJti] = Set(_key, Claims(c => { c["iss"] = "https://evil.example"; c["jti"] = badIssuerJti; })),
            ["not-its-jti"] = Set(_key, mismatched),
            ["not-a-string"] = 42,
        };
        string path = $"/ssf/v1/poll/{StreamId}";
        _handler.Map("POST", path, _ => CapturingHandler.Json(200, new JsonObject { ["sets"] = sets.DeepClone(), ["moreAvailable"] = true }.ToJsonString()));

        SsfPollResult result = await receiver.PollAsync(StreamId, new SsfPollOptions
        {
            MaxEvents = 10,
            ReturnImmediately = true,
            Ack = new[] { "a1", "a2" },
            SetErrs = new Dictionary<string, SetErr> { ["e1"] = SetErr.FromReason(SetFailureReason.InvalidIssuer), ["e2"] = new("invalid_key", "rotated") },
        });

        CapturingHandler.Captured sent = Assert.Single(_handler.To(path));
        Assert.True(JsonNode.DeepEquals(
            JsonNode.Parse("""{"maxEvents":10,"returnImmediately":true,"ack":["a1","a2"],"setErrs":{"e1":{"err":"invalid_issuer"},"e2":{"err":"invalid_key","description":"rotated"}}}"""),
            JsonNode.Parse(sent.Body!)), "the poll body is exactly what was given");
        Assert.Equal(new[] { $"Bearer {pollToken}" }, sent.Header("Authorization"));
        Assert.Empty(sent.Header("Cookie"));

        Assert.True(result.MoreAvailable);
        Assert.Equal(goodJti, Assert.Single(result.Events).Jti);
        Assert.Equal(3, result.Refused.Count);
        Assert.Contains(new RefusedSet(badIssuerJti, SetFailureReason.InvalidIssuer), result.Refused);
        Assert.Contains(new RefusedSet("not-its-jti", SetFailureReason.InvalidRequest), result.Refused);
        Assert.Contains(new RefusedSet("not-a-string", SetFailureReason.Malformed), result.Refused);

        await receiver.PollAsync(StreamId);
        Assert.Equal("{}", _handler.To(path)[1].Body);
        // Nothing was acknowledged on the caller's behalf: only the two polls went out.
        Assert.Equal(2, _handler.To(path).Count);
    }

    /// <summary>
    /// &#167;32.8 helper (8), contract 1.59 (&#167;34.2 P1, R-1 / CS-02): a batch of two whose second
    /// SET names an unknown kid while the refetch fails. Afterwards the first SET's jti is not in
    /// the store, or the first SET is returned in <c>events</c> — here, the second form: the first
    /// is returned and the second, unjudged, is in neither list and is not recorded.
    /// </summary>
    [Fact]
    public async Task APollBatchCutShortByAFailedKeyFetchKeepsNoJtiItDoesNotReturn()
    {
        var store = new SpyReplayStore();
        SsfReceiver receiver = new(_client, new SsfReceiverOptions
        {
            Issuer = Issuer,
            Audience = Audience,
            Keys = SsfKeySource.FromJwksUri($"https://axiam.test{JwksPath}"),
            AccessTokenProvider = _ => Task.FromResult(Sensitive<string>.Wrap(Secrets.Fresh())),
            ReplayStore = store,
            TimeProvider = _clock,
        });
        int jwksCalls = 0;
        _handler.Map("GET", JwksPath, _ => ++jwksCalls == 1
            ? CapturingHandler.Json(200, Jwks(_key))
            : CapturingHandler.Status(500));

        JsonObject first = Claims();
        JsonObject second = Claims();
        string firstJti = first["jti"]!.GetValue<string>();
        string secondJti = second["jti"]!.GetValue<string>();
        var sets = new JsonObject { [firstJti] = Set(_key, first), [secondJti] = Set(new SigningKey(), second) };
        _handler.Map("POST", $"/ssf/v1/poll/{StreamId}", _ => CapturingHandler.Json(200, new JsonObject { ["sets"] = sets.DeepClone() }.ToJsonString()));

        SsfPollResult? result = null;
        try
        {
            result = await receiver.PollAsync(StreamId);
        }
        catch (NetworkError)
        {
            // The first form: raised having recorded nothing — checked below.
        }

        Assert.Equal(2, jwksCalls);
        bool returned = result is not null && result.Events.Any(e => e.Jti == firstJti);
        Assert.True(returned || !store.Holds(firstJti), "poll left a jti recorded that it did not return");
        Assert.False(store.Holds(secondJti), "the unjudged SET was recorded");

        // This SDK's form: what was judged is returned, the unjudged SET is listed apart.
        Assert.NotNull(result);
        Assert.Equal(firstJti, Assert.Single(result!.Events).Jti);
        Assert.Empty(result.Refused);
        Assert.Equal(new[] { secondJti }, result.Unjudged);
    }

    /// <summary>
    /// &#167;34.2 P1/P3 (R-1 / CS-02): a replay store that cannot answer is no verdict either — the
    /// SETs judged before it are returned, the rest are unjudged and unrecorded; with nothing
    /// recorded yet, the poll raises the store's failure.
    /// </summary>
    [Fact]
    public async Task APollBatchCutShortByAFailingStoreKeepsNoJtiItDoesNotReturn()
    {
        var store = new SpyReplayStore { FailAfter = 1 };
        SsfReceiver receiver = new(_client, new SsfReceiverOptions
        {
            Issuer = Issuer,
            Audience = Audience,
            Keys = SsfKeySource.FromJwksUri($"https://axiam.test{JwksPath}"),
            AccessTokenProvider = _ => Task.FromResult(Sensitive<string>.Wrap(Secrets.Fresh())),
            ReplayStore = store,
            TimeProvider = _clock,
        });
        JsonObject[] batch = { Claims(), Claims(), Claims() };
        string[] jtis = batch.Select(c => c["jti"]!.GetValue<string>()).ToArray();
        var sets = new JsonObject();
        for (int i = 0; i < batch.Length; i++)
        {
            sets[jtis[i]] = Set(_key, batch[i]);
        }

        string path = $"/ssf/v1/poll/{StreamId}";
        _handler.Map("POST", path, _ => CapturingHandler.Json(200, new JsonObject { ["sets"] = sets.DeepClone() }.ToJsonString()));

        SsfPollResult result = await receiver.PollAsync(StreamId);
        Assert.Equal(jtis[0], Assert.Single(result.Events).Jti);
        Assert.Equal(new[] { jtis[1], jtis[2] }, result.Unjudged);
        Assert.Empty(result.Refused);
        Assert.True(store.Holds(jtis[0]));
        Assert.False(store.Holds(jtis[1]));
        Assert.False(store.Holds(jtis[2]));

        // Nothing recorded before the failure: the poll raises, and has recorded nothing.
        var broken = new SpyReplayStore { FailAfter = 0 };
        SsfReceiver failing = new(_client, new SsfReceiverOptions
        {
            Issuer = Issuer,
            Audience = Audience,
            Keys = SsfKeySource.FromJwksUri($"https://axiam.test{JwksPath}"),
            AccessTokenProvider = _ => Task.FromResult(Sensitive<string>.Wrap(Secrets.Fresh())),
            ReplayStore = broken,
            TimeProvider = _clock,
        });
        await Assert.ThrowsAsync<NetworkError>(() => failing.PollAsync(StreamId));
        Assert.All(jtis, j => Assert.False(broken.Holds(j)));
    }

    /// <summary>
    /// &#167;32.8 helper (6), contract 1.60 (&#167;34.2 P4, row B1 <i>verify</i>): a store that <b>cannot answer</b>
    /// gives no verdict. <c>VerifySetAsync</c> raises the &#167;2 type with no reason code &#8212; never
    /// <c>replayed</c>, never an accepted event &#8212; and <c>PollAsync</c> returns that SET in neither
    /// <c>Events</c> nor <c>Refused</c>, does not record its <c>jti</c> and does not put it in the
    /// acknowledgements, so the transmitter offers it again.
    /// </summary>
    [Fact]
    public async Task AStoreThatCannotAnswerGivesNoVerdict()
    {
        var store = new SpyReplayStore { FailAfter = 0 };
        SsfReceiver receiver = new(_client, new SsfReceiverOptions
        {
            Issuer = Issuer,
            Audience = Audience,
            Keys = SsfKeySource.FromJwksUri($"https://axiam.test{JwksPath}"),
            AccessTokenProvider = _ => Task.FromResult(Sensitive<string>.Wrap(Secrets.Fresh())),
            ReplayStore = store,
            TimeProvider = _clock,
        });

        // verify_set: the §2 type, not a SetVerificationError (which carries a reason code), and not `replayed`.
        JsonObject claims = Claims();
        string set = Set(_key, claims);
        Exception raised = await Assert.ThrowsAnyAsync<Exception>(() => receiver.VerifySetAsync(set));
        Assert.IsType<NetworkError>(raised);
        Assert.IsNotType<SetVerificationError>(raised);
        Assert.False(store.Holds(claims["jti"]!.GetValue<string>()));

        // The cause is chained (§2: a NetworkError carries one), and the store's own message is not lost.
        Assert.NotNull(raised.InnerException);
        Assert.Contains("replay store unavailable", raised.InnerException!.Message, StringComparison.Ordinal);

        // Once the store answers again, the same SET is accepted: it was never judged, so it was never refused.
        store.Recover();
        Assert.Equal(claims["jti"]!.GetValue<string>(), (await receiver.VerifySetAsync(set)).Jti);

        // poll: a SET whose store check cannot answer is in neither Events nor Refused, is not recorded
        // and is reported as unjudged -- so the caller has no jti to acknowledge for it.
        var broken = new SpyReplayStore { FailAfter = 1 };
        SsfReceiver polling = new(_client, new SsfReceiverOptions
        {
            Issuer = Issuer,
            Audience = Audience,
            Keys = SsfKeySource.FromJwksUri($"https://axiam.test{JwksPath}"),
            AccessTokenProvider = _ => Task.FromResult(Sensitive<string>.Wrap(Secrets.Fresh())),
            ReplayStore = broken,
            TimeProvider = _clock,
        });
        JsonObject[] batch = { Claims(), Claims() };
        string[] jtis = batch.Select(c => c["jti"]!.GetValue<string>()).ToArray();
        var sets = new JsonObject();
        for (int i = 0; i < batch.Length; i++)
        {
            sets[jtis[i]] = Set(_key, batch[i]);
        }

        _handler.Map("POST", $"/ssf/v1/poll/{StreamId}", _ => CapturingHandler.Json(200, new JsonObject { ["sets"] = sets.DeepClone() }.ToJsonString()));
        SsfPollResult result = await polling.PollAsync(StreamId);
        Assert.Equal(jtis[0], Assert.Single(result.Events).Jti);
        Assert.Empty(result.Refused);
        Assert.Equal(new[] { jtis[1] }, result.Unjudged);
        Assert.False(broken.Holds(jtis[1]));
    }

    /// <summary>A replay store that remembers what it recorded and can be made to fail.</summary>
    private sealed class SpyReplayStore : IReplayStore
    {
        private readonly HashSet<string> _held = new(StringComparer.Ordinal);

        /// <summary>When set, every call after this many successful records throws.</summary>
        public int? FailAfter { get; set; }

        public bool Holds(string jti) => _held.Contains(jti);

        /// <summary>The store answers again.</summary>
        public void Recover() => FailAfter = null;

        public bool CheckAndRecord(string jti, TimeSpan window)
        {
            if (FailAfter is { } n && _held.Count >= n)
            {
                throw new InvalidOperationException("replay store unavailable");
            }

            return _held.Add(jti);
        }
    }

    /// <summary>&#167;32.7: poll is not retried on a 400 (retry-enabled client), but is on a 503.</summary>
    [Fact]
    public async Task PollIsNotRetriedOnA4xxButIsOnA503()
    {
        SsfReceiver receiver = Receiver(_ => Task.FromResult(Sensitive<string>.Wrap(Secrets.Fresh())));
        string path = $"/ssf/v1/poll/{StreamId}";
        _handler.Map("POST", path, _ => CapturingHandler.Json(400, """{"error":"invalid_request","message":"maxEvents"}"""));
        await Assert.ThrowsAsync<ValidationError>(() => receiver.PollAsync(StreamId, new SsfPollOptions { MaxEvents = -1 }));
        Assert.Single(_handler.To(path));

        int calls = 0;
        _handler.Map("POST", path, _ => ++calls == 1
            ? CapturingHandler.Status(503)
            : CapturingHandler.Json(200, """{"sets":{},"moreAvailable":false}"""));
        SsfPollResult result = await receiver.PollAsync(StreamId);
        Assert.Equal(2, calls);
        Assert.Empty(result.Events);

        _handler.Map("POST", path, _ => CapturingHandler.Json(404, """{"error":"not_found","message":"no stream"}"""));
        await Assert.ThrowsAsync<NotFoundError>(() => receiver.PollAsync(StreamId));
    }

    /// <summary>No token provider → a local AuthError and no request.</summary>
    [Fact]
    public async Task PollWithoutATokenProviderIsRefusedLocally()
    {
        SsfReceiver receiver = Receiver();
        await Assert.ThrowsAsync<AuthError>(() => receiver.PollAsync(StreamId));
        Assert.Empty(_handler.Requests);
    }

    /// <summary>A JWKS fetch failure is a NetworkError, not a SET refusal — and it aborts a poll.</summary>
    [Fact]
    public async Task AJwksFailureIsANetworkErrorAndAbortsAPoll()
    {
        _handler.Map("GET", JwksPath, _ => CapturingHandler.Status(500));
        SsfReceiver receiver = Receiver(_ => Task.FromResult(Sensitive<string>.Wrap(Secrets.Fresh())));
        NetworkError e = await Assert.ThrowsAsync<NetworkError>(() => receiver.VerifySetAsync(Set(_key, Claims())));
        Assert.IsNotType<ValidationError>(e);

        JsonObject claims = Claims();
        _handler.Map("POST", $"/ssf/v1/poll/{StreamId}", _ => CapturingHandler.Json(200,
            new JsonObject { ["sets"] = new JsonObject { [claims["jti"]!.GetValue<string>()] = Set(_key, claims) } }.ToJsonString()));
        await Assert.ThrowsAsync<NetworkError>(() => receiver.PollAsync(StreamId));
    }

    /// <summary>Keys from a discovery document whose issuer matches; a mismatched issuer is refused.</summary>
    [Fact]
    public async Task DiscoveryProvidesTheJwksUriOnlyForTheConfiguredIssuer()
    {
        _handler.Map("GET", "/.well-known/ssf-configuration", _ => CapturingHandler.Json(200,
            new JsonObject { ["issuer"] = Issuer, ["jwks_uri"] = $"https://axiam.test{JwksPath}", ["spec_version"] = "1_0" }.ToJsonString()));
        var receiver = new SsfReceiver(_client, new SsfReceiverOptions
        {
            Issuer = Issuer,
            Audience = Audience,
            Keys = SsfKeySource.FromDiscoveryUrl("https://axiam.test/.well-known/ssf-configuration?tenant_id=7c1e"),
        });
        await receiver.VerifySetAsync(Set(_key, Claims()));
        Assert.Single(_handler.To(JwksPath));

        var wrong = new SsfReceiver(_client, new SsfReceiverOptions
        {
            Issuer = "https://elsewhere.example",
            Audience = Audience,
            Keys = SsfKeySource.FromDiscoveryUrl("https://axiam.test/.well-known/ssf-configuration"),
        });
        await Assert.ThrowsAsync<NetworkError>(() => wrong.VerifySetAsync(Set(_key, Claims(c => c["iss"] = "https://elsewhere.example"))));

        var plain = new SsfReceiver(_client, new SsfReceiverOptions
        {
            Issuer = Issuer,
            Audience = Audience,
            Keys = SsfKeySource.FromJwksUri("http://keys.example/jwks"),
        });
        await Assert.ThrowsAsync<NetworkError>(() => plain.VerifySetAsync(Set(_key, Claims())));
    }

    /// <summary>The RFC 8935 push codes and the memory store's expiry.</summary>
    [Fact]
    public void PushCodesAndTheMemoryStore()
    {
        (SetFailureReason Reason, string Code, string Push)[] table =
        {
            (SetFailureReason.Malformed, "malformed", "invalid_request"),
            (SetFailureReason.InvalidType, "invalid_type", "invalid_request"),
            (SetFailureReason.InvalidKey, "invalid_key", "invalid_key"),
            (SetFailureReason.InvalidIssuer, "invalid_issuer", "invalid_issuer"),
            (SetFailureReason.InvalidAudience, "invalid_audience", "invalid_audience"),
            (SetFailureReason.InvalidRequest, "invalid_request", "invalid_request"),
            (SetFailureReason.Replayed, "replayed", "invalid_request"),
        };
        foreach ((SetFailureReason reason, string code, string push) in table)
        {
            Assert.Equal(code, reason.Code());
            Assert.Equal(push, reason.PushErrorCode());
        }

        var store = new MemoryReplayStore(_clock);
        Assert.True(store.CheckAndRecord("a", TimeSpan.FromSeconds(60)));
        Assert.False(store.CheckAndRecord("a", TimeSpan.FromSeconds(60)));
        _clock.Advance(TimeSpan.FromSeconds(61));
        Assert.True(store.CheckAndRecord("a", TimeSpan.FromSeconds(60)));
        Assert.True(new MemoryReplayStore().CheckAndRecord("b", TimeSpan.FromDays(7)));
        Assert.Equal(8, typeof(SsfEventTypes).GetFields().Length);
    }

    /// <summary>An Ed25519 key generated at run time.</summary>
    private sealed class SigningKey
    {
        private readonly Ed25519PrivateKeyParameters _private;

        public SigningKey()
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
            _private = (Ed25519PrivateKeyParameters)pair.Private;
            Public = ((Ed25519PublicKeyParameters)pair.Public).GetEncoded();
            Kid = Convert.ToHexString(SHA256.HashData(Public))[..16].ToLowerInvariant();
        }

        public byte[] Public { get; }

        public string Kid { get; }

        public byte[] Sign(byte[] input)
        {
            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, _private);
            signer.BlockUpdate(input, 0, input.Length);
            return signer.GenerateSignature();
        }
    }
}

/// <summary>A clock a test moves by hand.</summary>
public sealed class ManualClock : TimeProvider
{
    private DateTimeOffset _now = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);

    /// <inheritdoc />
    public override DateTimeOffset GetUtcNow() => _now;

    /// <summary>Moves the clock forward.</summary>
    public void Advance(TimeSpan by) => _now += by;
}
