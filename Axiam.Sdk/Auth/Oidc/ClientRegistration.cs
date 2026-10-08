using System.Text.Json;
using System.Text.Json.Nodes;
using Axiam.Sdk.Core;

namespace Axiam.Sdk.Auth.Oidc;

/// <summary>
/// An RFC 7591 &#167;3.2.1 / RFC 7592 &#167;3 client information response — what
/// <see cref="AxiamClient.ReadClientRegistrationAsync"/> and
/// <see cref="AxiamClient.UpdateClientRegistrationAsync"/> return (CONTRACT.md &#167;28.12).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="RegistrationAccessToken"/> and <see cref="ClientSecret"/> are
/// <see cref="Sensitive{T}"/> (&#167;28.12.4): <see cref="object.ToString"/>, the
/// compiler-generated record printer and <c>System.Text.Json</c> all render them as
/// <c>[SENSITIVE]</c>.
/// </para>
/// <para>
/// Decoding is <b>tolerant</b>. Every member the server sent that this type does not name —
/// and a named member that arrived with an unexpected JSON type — is kept verbatim in
/// <see cref="Extra"/>. That matters because an update is a <b>full replacement</b>: a member
/// a read returned and an update left out is a member the server deletes. Passing a read's
/// result (or a <c>with</c>-expression over it) straight to
/// <see cref="AxiamClient.UpdateClientRegistrationAsync"/> therefore sends it back intact,
/// <c>jwks</c> / <c>jwks_uri</c> and the CIBA <c>backchannel_*</c> members included.
/// </para>
/// </remarks>
public sealed record ClientRegistration
{
    /// <summary>
    /// The members <see cref="AxiamClient.UpdateClientRegistrationAsync"/> never sends
    /// (&#167;28.12.2 rule 4): the server refuses the first four with
    /// <c>400 invalid_request</c>, and never accepts the client secret back.
    /// </summary>
    internal static readonly IReadOnlyList<string> ServerStatedMembers = new[]
    {
        "registration_access_token",
        "registration_client_uri",
        "client_secret_expires_at",
        "client_id_issued_at",
        "client_secret",
    };

    private static readonly HashSet<string> Modelled = new(StringComparer.Ordinal)
    {
        "client_id", "client_id_issued_at", "client_name", "redirect_uris", "grant_types",
        "response_types", "token_endpoint_auth_method", "scope", "registration_client_uri",
        "client_secret_expires_at", "jwks", "jwks_uri", "client_secret",
        "registration_access_token",
    };

    /// <summary>The client's <c>client_id</c>. Always sent on an update.</summary>
    public required string ClientId { get; init; }

    /// <summary>When the client id was issued (seconds since the epoch). Never sent on an update.</summary>
    public long? ClientIdIssuedAt { get; init; }

    /// <summary>The registered display name.</summary>
    public string? ClientName { get; init; }

    /// <summary>The registered redirect URIs, or <c>null</c> when the server sent none.</summary>
    public IReadOnlyList<string>? RedirectUris { get; init; }

    /// <summary>The registered grant types, or <c>null</c> when the server sent none.</summary>
    public IReadOnlyList<string>? GrantTypes { get; init; }

    /// <summary>The registered response types, or <c>null</c> when the server sent none.</summary>
    public IReadOnlyList<string>? ResponseTypes { get; init; }

    /// <summary>
    /// How the client authenticates at the token endpoint. The server refuses an update that
    /// changes it.
    /// </summary>
    public string? TokenEndpointAuthMethod { get; init; }

    /// <summary>The registered scope, space-separated.</summary>
    public string? Scope { get; init; }

    /// <summary>Where this registration is read, replaced and deleted. Never sent on an update.</summary>
    public string? RegistrationClientUri { get; init; }

    /// <summary>When the client secret expires (<c>0</c> = never). Never sent on an update.</summary>
    public long? ClientSecretExpiresAt { get; init; }

    /// <summary>The client's JWK Set, for a <c>private_key_jwt</c> client.</summary>
    public JsonElement? Jwks { get; init; }

    /// <summary>Where the client's JWK Set is published.</summary>
    public string? JwksUri { get; init; }

    /// <summary>
    /// The client secret — present only on the registration response itself, never on a read
    /// or an update. Never sent back.
    /// </summary>
    public Sensitive<string>? ClientSecret { get; init; }

    /// <summary>
    /// The registration access token — present on the registration response and,
    /// <b>rotated</b>, on every update response; absent on a read. Never sent in a body.
    /// </summary>
    public Sensitive<string>? RegistrationAccessToken { get; init; }

    /// <summary>Every other member of the response, verbatim (RFC 7591 &#167;3.2.1).</summary>
    public IReadOnlyDictionary<string, JsonElement> Extra { get; init; } =
        new Dictionary<string, JsonElement>(StringComparer.Ordinal);

    /// <summary>
    /// Decodes a client information response, tolerating unknown and mistyped members.
    /// </summary>
    /// <param name="json">The response body.</param>
    /// <returns>The decoded registration.</returns>
    /// <exception cref="NetworkError">The body is not a JSON object carrying a string <c>client_id</c>.</exception>
    public static ClientRegistration FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            return FromElement(document.RootElement);
        }
        catch (JsonException)
        {
            throw NetworkError.FromMessage("client registration response is not valid JSON");
        }
    }

    internal static ClientRegistration FromElement(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw NetworkError.FromMessage("client registration response is not a JSON object");
        }

        var extra = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (JsonProperty member in root.EnumerateObject())
        {
            if (!Modelled.Contains(member.Name))
            {
                extra[member.Name] = member.Value.Clone();
            }
        }

        string? Str(string name)
        {
            if (!root.TryGetProperty(name, out JsonElement value) || value.ValueKind == JsonValueKind.Null)
            {
                return null;
            }

            if (value.ValueKind == JsonValueKind.String)
            {
                return value.GetString();
            }

            // Keep a member of an unexpected type rather than drop it: a replacement must not
            // lose what the server holds.
            extra[name] = value.Clone();
            return null;
        }

        long? Int(string name)
        {
            if (!root.TryGetProperty(name, out JsonElement value) || value.ValueKind == JsonValueKind.Null)
            {
                return null;
            }

            if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out long parsed))
            {
                return parsed;
            }

            extra[name] = value.Clone();
            return null;
        }

        IReadOnlyList<string>? List(string name)
        {
            if (!root.TryGetProperty(name, out JsonElement value) || value.ValueKind == JsonValueKind.Null)
            {
                return null;
            }

            if (value.ValueKind != JsonValueKind.Array ||
                value.EnumerateArray().Any(item => item.ValueKind != JsonValueKind.String))
            {
                extra[name] = value.Clone();
                return null;
            }

            return value.EnumerateArray().Select(item => item.GetString()!).ToList();
        }

        string clientId = Str("client_id")
            ?? throw NetworkError.FromMessage("client registration response carries no client_id");
        JsonElement? jwks = root.TryGetProperty("jwks", out JsonElement jwksEl) &&
                            jwksEl.ValueKind != JsonValueKind.Null
            ? jwksEl.Clone()
            : null;
        string? secret = Str("client_secret");
        string? token = Str("registration_access_token");

        return new ClientRegistration
        {
            ClientId = clientId,
            ClientIdIssuedAt = Int("client_id_issued_at"),
            ClientName = Str("client_name"),
            RedirectUris = List("redirect_uris"),
            GrantTypes = List("grant_types"),
            ResponseTypes = List("response_types"),
            TokenEndpointAuthMethod = Str("token_endpoint_auth_method"),
            Scope = Str("scope"),
            RegistrationClientUri = Str("registration_client_uri"),
            ClientSecretExpiresAt = Int("client_secret_expires_at"),
            Jwks = jwks,
            JwksUri = Str("jwks_uri"),
            ClientSecret = secret is null ? null : Sensitive.Of(secret),
            RegistrationAccessToken = token is null ? null : Sensitive.Of(token),
            Extra = extra,
        };
    }

    /// <summary>
    /// The RFC 7592 &#167;2.2 replacement body: every member but the five the server states
    /// (&#167;28.12.2 rule 4), with <c>client_id</c> set to this registration's own.
    /// </summary>
    internal string ToUpdateBody()
    {
        var body = new JsonObject();
        foreach ((string name, JsonElement value) in Extra)
        {
            body[name] = JsonNode.Parse(value.GetRawText());
        }

        foreach (string name in ServerStatedMembers)
        {
            body.Remove(name);
        }

        body["client_id"] = ClientId;
        if (ClientName is not null)
        {
            body["client_name"] = ClientName;
        }

        if (RedirectUris is not null)
        {
            body["redirect_uris"] = new JsonArray(RedirectUris.Select(u => (JsonNode?)u).ToArray());
        }

        if (GrantTypes is not null)
        {
            body["grant_types"] = new JsonArray(GrantTypes.Select(u => (JsonNode?)u).ToArray());
        }

        if (ResponseTypes is not null)
        {
            body["response_types"] = new JsonArray(ResponseTypes.Select(u => (JsonNode?)u).ToArray());
        }

        if (TokenEndpointAuthMethod is not null)
        {
            body["token_endpoint_auth_method"] = TokenEndpointAuthMethod;
        }

        if (Scope is not null)
        {
            body["scope"] = Scope;
        }

        if (Jwks is { } jwks)
        {
            body["jwks"] = JsonNode.Parse(jwks.GetRawText());
        }

        if (JwksUri is not null)
        {
            body["jwks_uri"] = JwksUri;
        }

        return body.ToJsonString();
    }
}
