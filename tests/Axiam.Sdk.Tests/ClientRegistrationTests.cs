using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Axiam.Sdk.Auth.Oidc;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management;
using Axiam.Sdk.Options;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CONTRACT.md &#167;28.12 — RFC 7592 client configuration: the five &#167;28.12.6 tests and
/// the retry, decoding and error-shape details around them.
/// </summary>
public sealed class ClientRegistrationTests
{
    private static readonly Uri Base = new("https://axiam.test");
    private const string ClientId = "c-1f0e";
    private const string RefreshPath = "/api/v1/auth/refresh";

    private static string RegistrationPath => $"/oauth2/register/{ClientId}";

    private static string RegistrationUri => $"{Base.ToString().TrimEnd('/')}{RegistrationPath}?tenant_id={OidcTestKit.TenantGuid}";

    private static (AxiamClient Client, CapturingHandler Handler, string SessionToken) ClientWithSession(Uri? baseUrl = null)
    {
        var handler = new CapturingHandler();
        handler.Map("POST", RefreshPath, _ => CapturingHandler.Status(500));
        Uri url = baseUrl ?? Base;
        AxiamClient client = AxiamClient.CreateForTesting(
            url, OidcTestKit.TenantGuid, new AxiamClientOptions { BaseUrl = url, TenantId = OidcTestKit.TenantGuid }, handler);
        string session = Secrets.Fresh();
        FieldInfo field = typeof(AxiamClient).GetField("_cookieContainer", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var jar = (CookieContainer)field.GetValue(client)!;
        jar.Add(url, new Cookie("axiam_access", session));
        jar.Add(url, new Cookie("axiam_csrf", Secrets.Fresh()));
        return (client, handler, session);
    }

    private static string RegistrationBody(string? token = null, string? secret = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["client_id"] = ClientId,
            ["client_name"] = "Billing agent",
            ["redirect_uris"] = new[] { "https://app.example/cb" },
            ["grant_types"] = new[] { "authorization_code", "urn:openid:params:grant-type:ciba" },
            ["response_types"] = new[] { "code" },
            ["token_endpoint_auth_method"] = "client_secret_post",
            ["scope"] = "openid profile",
            ["registration_client_uri"] = RegistrationUri,
            ["client_id_issued_at"] = 1_760_000_000,
            ["client_secret_expires_at"] = 0,
            ["jwks_uri"] = "https://app.example/jwks",
            ["backchannel_token_delivery_mode"] = "poll",
        };
        if (token is not null)
        {
            body["registration_access_token"] = token;
        }

        if (secret is not null)
        {
            body["client_secret"] = secret;
        }

        return JsonSerializer.Serialize(body);
    }

    /// <summary>&#167;28.12.6 (1): another host, another port, http against https — refused, nothing sent.</summary>
    [Fact]
    public async Task AUriAtAnotherOriginIsRefusedLocallyAndNothingIsSent()
    {
        var (client, handler, _) = ClientWithSession();
        using (client)
        {
            var token = Sensitive<string>.Wrap(Secrets.Fresh());
            string[] refused =
            {
                $"https://evil.example{RegistrationPath}",
                $"https://axiam.test:8443{RegistrationPath}",
                $"http://axiam.test{RegistrationPath}",
                $"ftp://axiam.test{RegistrationPath}",
                RegistrationPath,
                "not a url",
            };
            foreach (string uri in refused)
            {
                await Assert.ThrowsAsync<ValidationError>(() => client.ReadClientRegistrationAsync(uri, token));
                await Assert.ThrowsAsync<ValidationError>(() => client.DeleteClientRegistrationAsync(uri, token));
                await Assert.ThrowsAsync<ValidationError>(() => client.UpdateClientRegistrationAsync(
                    uri, token, new ClientRegistration { ClientId = ClientId }));
            }

            Assert.Empty(handler.Requests);

            // The refusal names no part of the URI.
            ValidationError e = await Assert.ThrowsAsync<ValidationError>(
                () => client.ReadClientRegistrationAsync("https://evil.example/x", token));
            Assert.DoesNotContain("evil", e.Message, StringComparison.Ordinal);
        }
    }

    /// <summary>&#167;28.12.2 rule 1: http is allowed only against an http loopback base URL.</summary>
    [Fact]
    public async Task HttpIsAcceptedOnlyAgainstAnHttpLoopbackBase()
    {
        var loopback = new Uri("http://127.0.0.1:8080");
        var (client, handler, _) = ClientWithSession(loopback);
        using (client)
        {
            handler.Map("GET", RegistrationPath, _ => CapturingHandler.Json(200, RegistrationBody()));
            ClientRegistration read = await client.ReadClientRegistrationAsync(
                $"http://127.0.0.1:8080{RegistrationPath}", Sensitive<string>.Wrap(Secrets.Fresh()));
            Assert.Equal(ClientId, read.ClientId);
            Assert.Single(handler.Requests);
        }

        var internalBase = new Uri("http://iam.internal:8080");
        var (other, otherHandler, _) = ClientWithSession(internalBase);
        using (other)
        {
            await Assert.ThrowsAsync<ValidationError>(() => other.ReadClientRegistrationAsync(
                $"http://iam.internal:8080{RegistrationPath}", Sensitive<string>.Wrap(Secrets.Fresh())));
            Assert.Empty(otherHandler.Requests);
        }
    }

    /// <summary>
    /// &#167;28.12.6 (2): read and delete send the bearer only — no body, no SDK session token,
    /// no session cookie or CSRF header — and the given query verbatim.
    /// </summary>
    [Fact]
    public async Task ReadAndDeleteSendTheBearerOnlyAndKeepTheQueryVerbatim()
    {
        var (client, handler, session) = ClientWithSession();
        using (client)
        {
            // The session is real: an ordinary call carries it.
            handler.Map("GET", "/api/v1/auth/me", _ => CapturingHandler.Status(500));
            await client.TransportHttpClient.GetAsync("/api/v1/auth/me");
            Assert.Contains($"Bearer {session}", handler.Requests[0].Header("Authorization"));
            handler.Requests.Clear();

            string token = Secrets.Fresh();
            handler.Map("GET", RegistrationPath, _ => CapturingHandler.Json(200, RegistrationBody()));
            handler.Map("DELETE", RegistrationPath, _ => CapturingHandler.Status(204));

            ClientRegistration read = await client.ReadClientRegistrationAsync(RegistrationUri, Sensitive<string>.Wrap(token));
            await client.DeleteClientRegistrationAsync(RegistrationUri, Sensitive<string>.Wrap(token));

            Assert.Equal(2, handler.Requests.Count);
            foreach (CapturingHandler.Captured sent in handler.Requests)
            {
                Assert.Equal(new[] { $"Bearer {token}" }, sent.Header("Authorization"));
                Assert.Null(sent.Body);
                Assert.Empty(sent.Header("Cookie"));
                Assert.Empty(sent.Header("X-CSRF-Token"));
                Assert.Equal($"?tenant_id={OidcTestKit.TenantGuid}", sent.Uri.Query);
                Secrets.AssertAbsent(string.Join("\n", sent.Headers.SelectMany(h => h.Value)), session, "session token on a registration request");
            }

            Assert.Equal("GET", handler.Requests[0].Method);
            Assert.Equal("DELETE", handler.Requests[1].Method);
            Assert.Equal(ClientId, read.ClientId);
            Assert.Null(read.RegistrationAccessToken);
            Assert.Equal("poll", read.Extra["backchannel_token_delivery_mode"].GetString());
        }
    }

    /// <summary>
    /// &#167;28.12.6 (3): the update body drops the five server-stated members, keeps
    /// <c>client_id</c> and every other member, and the rotated token comes back.
    /// </summary>
    [Fact]
    public async Task UpdateDropsTheFiveServerStatedMembersAndReturnsTheRotatedToken()
    {
        var (client, handler, _) = ClientWithSession();
        using (client)
        {
            string presented = Secrets.Fresh();
            string rotated = Secrets.Fresh();
            ClientRegistration fromRead = ClientRegistration.FromJson(RegistrationBody(presented, Secrets.Fresh()));
            Assert.NotNull(fromRead.RegistrationAccessToken);
            Assert.NotNull(fromRead.ClientSecret);
            Assert.NotNull(fromRead.ClientIdIssuedAt);
            Assert.NotNull(fromRead.ClientSecretExpiresAt);
            Assert.NotNull(fromRead.RegistrationClientUri);

            handler.Map("PUT", RegistrationPath, _ => CapturingHandler.Json(200, RegistrationBody(rotated)));
            ClientRegistration updated = await client.UpdateClientRegistrationAsync(
                RegistrationUri, Sensitive<string>.Wrap(presented), fromRead with { ClientName = "Billing agent v2" });

            CapturingHandler.Captured sent = Assert.Single(handler.Requests);
            Assert.Equal("PUT", sent.Method);
            Assert.Equal(new[] { $"Bearer {presented}" }, sent.Header("Authorization"));
            using JsonDocument body = JsonDocument.Parse(sent.Body!);
            var keys = body.RootElement.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
            foreach (string stated in new[]
                     {
                         "registration_access_token", "registration_client_uri", "client_secret_expires_at",
                         "client_id_issued_at", "client_secret",
                     })
            {
                Assert.DoesNotContain(stated, keys);
            }

            Assert.Equal(ClientId, body.RootElement.GetProperty("client_id").GetString());
            Assert.Equal("Billing agent v2", body.RootElement.GetProperty("client_name").GetString());
            Assert.Equal("poll", body.RootElement.GetProperty("backchannel_token_delivery_mode").GetString());
            Assert.Equal("https://app.example/jwks", body.RootElement.GetProperty("jwks_uri").GetString());
            Assert.Equal(2, body.RootElement.GetProperty("grant_types").GetArrayLength());
            Assert.Equal(rotated, updated.RegistrationAccessToken!.Value.Expose());
        }
    }

    /// <summary>&#167;28.12.6 (3) / rule 5: a 503 on update and on delete is not retried — on a retry-enabled client.</summary>
    [Fact]
    public async Task NeitherWriteIsRetriedOnA503ButTheReadIs()
    {
        var (client, handler, _) = ClientWithSession();
        using (client)
        {
            var token = Sensitive<string>.Wrap(Secrets.Fresh());
            handler.Map("PUT", RegistrationPath, _ => CapturingHandler.Status(503));
            handler.Map("DELETE", RegistrationPath, _ => CapturingHandler.Status(503));

            await Assert.ThrowsAsync<NetworkError>(() => client.UpdateClientRegistrationAsync(
                RegistrationUri, token, new ClientRegistration { ClientId = ClientId }));
            Assert.Single(handler.To(RegistrationPath));

            await Assert.ThrowsAsync<NetworkError>(() => client.DeleteClientRegistrationAsync(RegistrationUri, token));
            Assert.Equal(2, handler.To(RegistrationPath).Count);

            int reads = 0;
            handler.Map("GET", RegistrationPath, _ => ++reads == 1
                ? CapturingHandler.Status(503)
                : CapturingHandler.Json(200, RegistrationBody()));
            ClientRegistration read = await client.ReadClientRegistrationAsync(RegistrationUri, token);
            Assert.Equal(ClientId, read.ClientId);
            Assert.Equal(2, reads);
        }
    }

    /// <summary>Rule 5: the read is never retried on a 4xx other than 408/429 — a bodiless 400 included.</summary>
    [Fact]
    public async Task TheReadIsNotRetriedOnABodiless400()
    {
        var (client, handler, _) = ClientWithSession();
        using (client)
        {
            handler.Map("GET", RegistrationPath, _ => CapturingHandler.Status(400));
            NetworkError e = await Assert.ThrowsAsync<NetworkError>(
                () => client.ReadClientRegistrationAsync(RegistrationUri, Sensitive<string>.Wrap(Secrets.Fresh())));
            Assert.IsNotType<ValidationError>(e);
            Assert.Single(handler.Requests);
        }
    }

    /// <summary>&#167;28.12.6 (4): a 401 invalid_token is an OAuthProtocolError and refreshes nothing.</summary>
    [Fact]
    public async Task A401InvalidTokenIsAnOAuthProtocolErrorAndRefreshesNothing()
    {
        var (client, handler, _) = ClientWithSession();
        using (client)
        {
            handler.Map("GET", RegistrationPath, _ =>
            {
                HttpResponseMessage r = CapturingHandler.Json(401, """{"error":"invalid_token","error_description":"The access token is invalid"}""");
                r.Headers.WwwAuthenticate.ParseAdd("Bearer error=\"invalid_token\"");
                return r;
            });
            handler.Map("DELETE", RegistrationPath, _ => CapturingHandler.Json(401, """{"error":"invalid_token"}"""));
            var token = Sensitive<string>.Wrap(Secrets.Fresh());

            OAuthProtocolError read = await Assert.ThrowsAsync<OAuthProtocolError>(
                () => client.ReadClientRegistrationAsync(RegistrationUri, token));
            Assert.Equal("invalid_token", read.Error);

            // error_description is optional (RFC 6749 §5.2).
            OAuthProtocolError delete = await Assert.ThrowsAsync<OAuthProtocolError>(
                () => client.DeleteClientRegistrationAsync(RegistrationUri, token));
            Assert.Equal("invalid_token", delete.Error);

            Assert.Empty(handler.To(RefreshPath));
            Assert.Equal(2, handler.To(RegistrationPath).Count);
        }
    }

    /// <summary>&#167;28.12.6 (4): a 400 invalid_client_metadata likewise; a 204 on delete returns normally.</summary>
    [Fact]
    public async Task A400InvalidClientMetadataIsAnOAuthProtocolErrorAndA204DeleteSucceeds()
    {
        var (client, handler, _) = ClientWithSession();
        using (client)
        {
            handler.Map("PUT", RegistrationPath, _ => CapturingHandler.Json(
                400, """{"error":"invalid_client_metadata","error_description":"scope widens the tenant policy"}"""));
            handler.Map("DELETE", RegistrationPath, _ => CapturingHandler.Status(204));
            var token = Sensitive<string>.Wrap(Secrets.Fresh());

            OAuthProtocolError e = await Assert.ThrowsAsync<OAuthProtocolError>(() => client.UpdateClientRegistrationAsync(
                RegistrationUri, token, new ClientRegistration { ClientId = ClientId, Scope = "openid admin" }));
            Assert.Equal("invalid_client_metadata", e.Error);
            Assert.Equal("scope widens the tenant policy", e.ErrorDescription);

            await client.DeleteClientRegistrationAsync(RegistrationUri, token);
            Assert.Empty(handler.To(RefreshPath));
        }
    }

    /// <summary>
    /// &#167;28.12.6 (5): neither the token nor the secret reaches ToString, the record printer,
    /// a JSON serialization for logs, or an error raised by an operation given the token.
    /// </summary>
    [Fact]
    public async Task NeitherTheTokenNorTheSecretReachesAnyRendering()
    {
        string token = Secrets.Fresh();
        string secret = Secrets.Fresh();
        ClientRegistration registration = ClientRegistration.FromJson(RegistrationBody(token, secret));
        Assert.Equal(token, registration.RegistrationAccessToken!.Value.Expose());
        Assert.Equal(secret, registration.ClientSecret!.Value.Expose());

        foreach ((string label, string rendering) in new[]
                 {
                     ("ToString", registration.ToString()),
                     ("token ToString", registration.RegistrationAccessToken.ToString()!),
                     ("Json", JsonSerializer.Serialize(registration)),
                     ("interpolation", $"{registration}"),
                 })
        {
            Secrets.AssertAbsent(rendering, token, label);
            Secrets.AssertAbsent(rendering, secret, label);
        }

        var (client, handler, _) = ClientWithSession();
        using (client)
        {
            handler.Map("GET", RegistrationPath, _ => CapturingHandler.Json(401, """{"error":"invalid_token"}"""));
            handler.Map("PUT", RegistrationPath, _ => CapturingHandler.Status(503));
            Exception read = await Assert.ThrowsAnyAsync<Exception>(
                () => client.ReadClientRegistrationAsync(RegistrationUri, Sensitive<string>.Wrap(token)));
            Exception update = await Assert.ThrowsAnyAsync<Exception>(
                () => client.UpdateClientRegistrationAsync(RegistrationUri, Sensitive<string>.Wrap(token), registration));
            Exception refused = await Assert.ThrowsAnyAsync<Exception>(
                () => client.ReadClientRegistrationAsync("https://evil.example/x", Sensitive<string>.Wrap(token)));
            foreach (Exception e in new[] { read, update, refused })
            {
                Secrets.AssertAbsent(e.ToString(), token, $"{e.GetType().Name} rendering");
                Secrets.AssertAbsent(e.ToString(), secret, $"{e.GetType().Name} rendering");
            }
        }
    }

    /// <summary>Decoding is tolerant: unknown and mistyped members are kept, and dropped from the update body when server-stated.</summary>
    [Fact]
    public void DecodingKeepsUnknownAndMistypedMembers()
    {
        ClientRegistration r = ClientRegistration.FromJson(
            """{"client_id":"c1","client_id_issued_at":"not-a-number","redirect_uris":["https://a"],"backchannel_client_notification_endpoint":"https://n","jwks":{"keys":[]},"grant_types":[1]}""");
        Assert.Equal("not-a-number", r.Extra["client_id_issued_at"].GetString());
        Assert.Equal("https://n", r.Extra["backchannel_client_notification_endpoint"].GetString());
        Assert.Null(r.ClientIdIssuedAt);
        Assert.Null(r.GrantTypes);
        Assert.True(r.Extra.ContainsKey("grant_types"));
        Assert.Equal(new[] { "https://a" }, r.RedirectUris);

        using JsonDocument body = JsonDocument.Parse(r.ToUpdateBody());
        Assert.False(body.RootElement.TryGetProperty("client_id_issued_at", out _));
        Assert.Equal("https://n", body.RootElement.GetProperty("backchannel_client_notification_endpoint").GetString());
        Assert.Equal(JsonValueKind.Object, body.RootElement.GetProperty("jwks").ValueKind);
        Assert.Equal(JsonValueKind.Array, body.RootElement.GetProperty("grant_types").ValueKind);

        Assert.Throws<NetworkError>(() => ClientRegistration.FromJson("[]"));
        Assert.Throws<NetworkError>(() => ClientRegistration.FromJson("""{"x":1}"""));
        Assert.Throws<NetworkError>(() => ClientRegistration.FromJson("{"));
    }

    /// <summary>A success body that is not a registration is a NetworkError, not a crash.</summary>
    [Fact]
    public async Task AnUnparseableSuccessBodyIsANetworkError()
    {
        var (client, handler, _) = ClientWithSession();
        using (client)
        {
            handler.Map("GET", RegistrationPath, _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("<html/>", Encoding.UTF8, "text/html"),
            });
            await Assert.ThrowsAsync<NetworkError>(
                () => client.ReadClientRegistrationAsync(RegistrationUri, Sensitive<string>.Wrap(Secrets.Fresh())));
        }
    }
}
