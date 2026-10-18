using System.Text.Json;
using Axiam.Sdk.Core;
using Axiam.Sdk.Management.Models;

namespace Axiam.Sdk.Management;

/// <summary>
/// A description of the tenant you want (CONTRACT.md &#167;27.6).
/// </summary>
/// <remarks>
/// <para>
/// A manifest states what should <b>exist</b>. It is not a diff and not a migration:
/// reconciling it against a tenant that already matches writes nothing, and reconciling
/// it twice is the same as reconciling it once.
/// </para>
/// <para>
/// What it never does is delete. Something the manifest does not mention is something
/// the manifest has no opinion about, not something it wants gone (&#167;27.6 rule 4) —
/// otherwise adopting a manifest for five roles would be a request to remove every
/// other role in the tenant.
/// </para>
/// <para>
/// Keys (<c>docs</c>, <c>editor</c>, <c>alice</c>) are <b>manifest-local</b> and never
/// reach the server. They exist so one entry can name another before either has an
/// identifier, which is what lets a manifest be written before anything in it exists.
/// </para>
/// </remarks>
public sealed record ManagementManifest
{
    /// <summary>The resource tree, with its scopes.</summary>
    public IReadOnlyList<ResourceSpec> Resources { get; init; } = Array.Empty<ResourceSpec>();

    /// <summary>The permissions that should exist.</summary>
    public IReadOnlyList<PermissionSpec> Permissions { get; init; } = Array.Empty<PermissionSpec>();

    /// <summary>The roles, with the permissions they grant.</summary>
    public IReadOnlyList<RoleSpec> Roles { get; init; } = Array.Empty<RoleSpec>();

    /// <summary>The groups, with the roles they hold.</summary>
    public IReadOnlyList<GroupSpec> Groups { get; init; } = Array.Empty<GroupSpec>();

    /// <summary>The users, with their roles and group memberships.</summary>
    public IReadOnlyList<UserSpec> Users { get; init; } = Array.Empty<UserSpec>();

    /// <summary>
    /// The service accounts, with their roles (CONTRACT.md &#167;27.6.1, contract 1.51).
    /// </summary>
    /// <remarks>
    /// Reconciled by <see cref="ServiceAccountSpec.Name"/> — the server does not enforce
    /// it unique (only <c>client_id</c> is indexed), so a stated name matching more than
    /// one existing account fails <c>PlanAsync</c>/<c>ApplyAsync</c> client-side, before
    /// any write. A <c>Create</c> action's outcome carries the one-time
    /// <c>client_secret</c> (&#167;27.5 rule 5), kept even when a LATER action of the same
    /// apply fails — see <see cref="ApplyReport.CreatedServiceAccounts"/>.
    /// </remarks>
    public IReadOnlyList<ServiceAccountSpec> ServiceAccounts { get; init; } = Array.Empty<ServiceAccountSpec>();

    /// <summary>
    /// The tenant's <c>Session-Timeout</c> cap, a <b>singleton</b> (CONTRACT.md &#167;27.6.2,
    /// contract 1.62): the tenant has exactly one, so a manifest carries at most one and it has no key.
    /// <c>null</c> leaves the tenant's cap alone.
    /// </summary>
    /// <remarks>
    /// Never <c>Create</c>d (the default, <c>version</c> 0, always exists) and never pruned: it is
    /// <c>NoChange</c> or <c>Update</c>. Written <b>first</b> of the <c>network</c> actions, because
    /// a profile's timeout is checked against the cap at the write. Human-only (&#167;36.1).
    /// </remarks>
    public NetworkPolicySpec? NetworkPolicy { get; init; }

    /// <summary>
    /// The network segments (CONTRACT.md &#167;27.6.2, contract 1.62), reconciled by their natural
    /// key: <b>site + kind + name</b>, where kind is the <b>wire</b> spelling
    /// (<see cref="NetworkSegmentKind.Access"/> or <see cref="NetworkSegmentKind.Quarantine"/>).
    /// </summary>
    public IReadOnlyList<NetworkSegmentSpec> NetworkSegments { get; init; } = Array.Empty<NetworkSegmentSpec>();

    /// <summary>
    /// The segments' reply profiles (CONTRACT.md &#167;27.6.2, contract 1.62), reconciled by the
    /// segment they belong to: a profile has no name or id of its own.
    /// </summary>
    public IReadOnlyList<NetworkProfileSpec> NetworkProfiles { get; init; } = Array.Empty<NetworkProfileSpec>();

    /// <summary>A manifest that describes nothing, and therefore changes nothing.</summary>
    /// <returns>An empty manifest.</returns>
    public static ManagementManifest Empty() => new();

    /// <summary>Starts a <see cref="ManifestBuilder"/>.</summary>
    /// <returns>A fresh builder.</returns>
    public static ManifestBuilder Builder() => new();

    /// <summary>One resource, and the scopes beneath it.</summary>
    /// <param name="Key">Manifest-local identifier, referenced by Parent and by grants.</param>
    /// <param name="Name">The resource's name, as the server stores it.</param>
    /// <param name="ResourceType">The resource's type.</param>
    /// <param name="Parent">The Key of this resource's parent, or <c>null</c> for a root.</param>
    /// <param name="Scopes">The scopes that should exist under this resource.</param>
    /// <param name="Metadata">
    /// An optional JSON object (CONTRACT.md &#167;27.6.1 item 1, contract 1.51). Sent on
    /// <c>Create</c>, and on <c>Update</c> when stated and it differs from the server's
    /// value — compared by JSON value equality of the WHOLE object, never a key-by-key
    /// merge, so a stated <c>{}</c> matches what the server stores for none and an
    /// unstated <see cref="Metadata"/> is silent (never an assertion to clear it).
    /// </param>
    public sealed record ResourceSpec(
        string Key,
        string Name,
        string ResourceType,
        string? Parent = null,
        IReadOnlyList<ScopeSpec>? Scopes = null,
        JsonElement? Metadata = null);

    /// <summary>One scope beneath a resource.</summary>
    /// <param name="Key">Manifest-local identifier, referenced by a grant's scope list.</param>
    /// <param name="Name">The scope's name.</param>
    /// <param name="Description">What the scope is for.</param>
    public sealed record ScopeSpec(string Key, string Name, string Description);

    /// <summary>One permission.</summary>
    /// <param name="Key">Manifest-local identifier, referenced by grants.</param>
    /// <param name="Action">The action this permission allows, e.g. <c>document:read</c>.</param>
    /// <param name="Description">What the permission is for.</param>
    public sealed record PermissionSpec(string Key, string Action, string Description);

    /// <summary>One grant of a permission to a role.</summary>
    /// <param name="Permission">The PermissionSpec key being granted.</param>
    /// <param name="Effect">
    /// <c>"allow"</c>, <c>"deny"</c>, or <c>null</c> for the server's default. AXIAM's
    /// RBAC is DENY-OVERRIDE: a deny beats every allow that reaches the same principal,
    /// at any depth of the resource hierarchy. It is not "the more specific rule wins".
    /// </param>
    /// <param name="Scopes">
    /// The ScopeSpec keys this grant is narrowed to; empty grants across the whole
    /// resource.
    /// </param>
    public sealed record GrantSpec(
        string Permission,
        string? Effect = null,
        IReadOnlyList<string>? Scopes = null);

    /// <summary>One role, and what it grants.</summary>
    /// <param name="Key">Manifest-local identifier.</param>
    /// <param name="Name">The role's name.</param>
    /// <param name="Description">What the role is for.</param>
    /// <param name="Global">Whether the role applies across every resource.</param>
    /// <param name="Grants">The permissions this role should hold.</param>
    public sealed record RoleSpec(
        string Key,
        string Name,
        string Description,
        bool Global = false,
        IReadOnlyList<GrantSpec>? Grants = null);

    /// <summary>One group, and the roles it holds.</summary>
    /// <param name="Key">Manifest-local identifier.</param>
    /// <param name="Name">The group's name.</param>
    /// <param name="Description">What the group is for.</param>
    /// <param name="Roles">The roles this group should hold — a role key, or a
    /// <see cref="RoleBinding"/> naming a resource and/or <c>inherit</c>.</param>
    public sealed record GroupSpec(
        string Key,
        string Name,
        string Description,
        IReadOnlyList<RoleBinding>? Roles = null);

    /// <summary>One user, with their roles and group memberships.</summary>
    /// <param name="Key">Manifest-local identifier.</param>
    /// <param name="Username">The user's username.</param>
    /// <param name="Email">The user's email address.</param>
    /// <param name="InitialPassword">
    /// The password to CREATE the user with. Used only when the user does not exist: a
    /// manifest that mentions a password is not a request to reset one, so reconciling
    /// against an existing user never sends it (&#167;27.6 rule 3).
    /// </param>
    /// <param name="Roles">The roles this user should hold directly — a role key, or a
    /// <see cref="RoleBinding"/> naming a resource and/or <c>inherit</c>.</param>
    /// <param name="Groups">The GroupSpec keys this user should belong to.</param>
    public sealed record UserSpec(
        string Key,
        string Username,
        string Email,
        Sensitive<string>? InitialPassword = null,
        IReadOnlyList<RoleBinding>? Roles = null,
        IReadOnlyList<string>? Groups = null);

    /// <summary>
    /// One service account, and the roles it holds (CONTRACT.md &#167;27.6.1 item 3,
    /// contract 1.51).
    /// </summary>
    /// <param name="Key">Manifest-local identifier.</param>
    /// <param name="Name">
    /// The account's name — the natural key <c>ApplyAsync</c>/<c>PlanAsync</c> reconcile
    /// by. The server does NOT enforce it unique (only <c>client_id</c> is indexed): a
    /// stated name matching more than one existing account fails client-side before any
    /// write, rather than picking one.
    /// </param>
    /// <param name="Description">What the account is for. The only field <c>Update</c>
    /// reconciles — <c>status</c> is not a manifest field in contract 1.51.</param>
    /// <param name="Roles">The roles this account should hold — a role key, or a
    /// <see cref="RoleBinding"/> naming a resource and/or <c>inherit</c>. Group
    /// membership of a service account is not a manifest field in contract 1.51.</param>
    public sealed record ServiceAccountSpec(
        string Key,
        string Name,
        string? Description = null,
        IReadOnlyList<RoleBinding>? Roles = null);

    /// <summary>
    /// One network segment (CONTRACT.md &#167;27.6.2 item 1, contract 1.62): a node of the reserved
    /// <c>/network</c> subtree with a VLAN and a <c>Filter-Id</c> envelope.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The natural key is <see cref="Site"/> + <see cref="Kind"/> + <see cref="Name"/>; the three
    /// never change (&#167;36.3 rule 4) and so are never drift. Every other member is a field,
    /// reconciled by &#167;27.6 rule 3: a <c>null</c> (unstated) member is silent, and on an
    /// <c>Update</c> is <b>carried from the read</b>, because the replacement body would
    /// otherwise clear it.
    /// </para>
    /// <para>
    /// <b>Judged on the read.</b> Every stated member is compared with the value the read returns.
    /// <see cref="FilterIds"/> is compared <b>as a set</b>: the same names in another order are
    /// <c>NoChange</c>, a list that repeats a name is refused at <c>PlanAsync</c> with zero wire
    /// calls, and when the SDK writes the segment it sends the names in the order stated here.
    /// </para>
    /// </remarks>
    /// <param name="Key">Manifest-local identifier, referenced by <see cref="NetworkProfileSpec.Segment"/>.</param>
    /// <param name="Site">The wire <c>site_key</c> (a single-site tenant uses <c>default</c>).</param>
    /// <param name="Kind">
    /// <see cref="NetworkSegmentKind.Access"/> or <see cref="NetworkSegmentKind.Quarantine"/>, the wire spelling.
    /// <see cref="NetworkSegmentKind.Unknown"/> is refused: it is a value this SDK decodes, never one it sends.
    /// </param>
    /// <param name="Name">The segment's name.</param>
    /// <param name="VlanId">The segment's VLAN.</param>
    /// <param name="Rank">
    /// The placement rank of an access segment. <c>null</c> is unstated;
    /// <see cref="JsonNullable{T}.Null"/> states "none" (left out of the body, which is how a replacement clears it).
    /// </param>
    /// <param name="FilterIds">The segment's <c>Filter-Id</c> envelope, or <c>null</c> when unstated.</param>
    /// <param name="Enabled">Whether the segment is a placement candidate, or <c>null</c> when unstated.</param>
    public sealed record NetworkSegmentSpec(
        string Key,
        string Site,
        NetworkSegmentKind Kind,
        string Name,
        int VlanId,
        JsonNullable<int>? Rank = null,
        IReadOnlyList<string>? FilterIds = null,
        bool? Enabled = null);

    /// <summary>
    /// A segment's reply profile (CONTRACT.md &#167;27.6.2 item 1, contract 1.62), addressed by its
    /// segment.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Judged on the read.</b> The profile read is the <b>effective</b> one, so
    /// <see cref="SessionTimeoutSecs"/> is compared with the value lowered to the tenant's cap:
    /// a profile whose stored timeout is above a lowered cap reads as the cap, and a manifest stating
    /// the cap is <c>NoChange</c>. A manifest that states a value <b>above</b> the cap differs from the
    /// read, so <c>PlanAsync</c> shows an <c>Update</c>; <c>ApplyAsync</c> then sends the replace, the server
    /// refuses it (<c>403</c> <c>authorization_denied</c>, the write gate's H3), and that is the action's
    /// failure: reported as the server gave it, <c>ApplyAsync</c> stops, nothing is retried, adjusted or
    /// lowered by the SDK (&#167;27.6.2 item 3).
    /// </para>
    /// <para>
    /// A stated <see cref="JsonNullable{T}.Null"/> is "none": the member is left <b>out</b> of the body.
    /// </para>
    /// </remarks>
    /// <param name="Segment">The <see cref="NetworkSegmentSpec.Key"/> of a segment of this manifest.</param>
    /// <param name="SessionTimeoutSecs">The <c>Session-Timeout</c> in seconds.</param>
    /// <param name="TerminationAction">The <c>Termination-Action</c>, or <c>null</c> when unstated.</param>
    /// <param name="IdleTimeoutSecs">The <c>Idle-Timeout</c>; <c>null</c> unstated, <see cref="JsonNullable{T}.Null"/> none.</param>
    /// <param name="FilterId">One of the segment's <c>filter_ids</c>; <c>null</c> unstated, <see cref="JsonNullable{T}.Null"/> none.</param>
    /// <param name="ServiceType">The <c>Service-Type</c>; <c>null</c> unstated, <see cref="JsonNullable{T}.Null"/> none.</param>
    public sealed record NetworkProfileSpec(
        string Segment,
        int SessionTimeoutSecs,
        RadiusTerminationAction? TerminationAction = null,
        JsonNullable<int>? IdleTimeoutSecs = null,
        JsonNullable<string>? FilterId = null,
        JsonNullable<RadiusServiceType>? ServiceType = null);

    /// <summary>The tenant's <c>Session-Timeout</c> cap (CONTRACT.md &#167;27.6.2 item 1, contract 1.62).</summary>
    /// <param name="SessionTimeoutMaxSecs">The cap in seconds; the server accepts 300 to 86 400.</param>
    public sealed record NetworkPolicySpec(int SessionTimeoutMaxSecs);

    /// <summary>
    /// One role binding on a group, user or service account (CONTRACT.md &#167;27.6.1
    /// item 2, contract 1.51) — either shape a manifest's <c>roles[]</c> entry can take.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Implicitly convertible from a bare role key (<c>(RoleBinding)"editor"</c>, and
    /// every call site in this SDK that used to take a <c>string</c> role key still
    /// compiles unchanged) — the plain shape every SDK had before contract 1.51: no
    /// resource, and so no inheritance question.
    /// </para>
    /// <para>
    /// The natural key within one subject's <see cref="ManagementManifest.GroupSpec.Roles"/>/
    /// <see cref="ManagementManifest.UserSpec.Roles"/>/
    /// <see cref="ManagementManifest.ServiceAccountSpec.Roles"/> is <see cref="Role"/>
    /// alone — the server keys an assignment on <c>(subject, role)</c> with no resource
    /// component (<c>has_role</c> is <c>UNIQUE(in, out)</c>), so one role bound twice to
    /// one subject — plain and scoped included — describes a state the server cannot
    /// hold. <c>PlanAsync</c>/<c>ApplyAsync</c> reject that before any request, naming the
    /// subject and the role (&#167;27.6.1's normative rule).
    /// </para>
    /// </remarks>
    /// <param name="Role">The <see cref="RoleSpec"/> key being bound.</param>
    /// <param name="Resource">
    /// The <see cref="ResourceSpec"/> key this binding is scoped to, or <c>null</c> for a
    /// plain (unscoped) binding.
    /// </param>
    /// <param name="Inherit">
    /// Whether the binding also reaches the descendants of <see cref="Resource"/>.
    /// Defaults to <c>true</c>, and reaches the wire ONLY as <c>false</c> — an inheritable
    /// binding's request body stays byte-for-byte a pre-1.51 body. A global role
    /// (<see cref="RoleSpec.Global"/>) bound with <c>Inherit: false</c> is refused by the
    /// server with <c>400</c> (a global role ignores resource scope); this is checked
    /// client-side too, before any request.
    /// </param>
    public sealed record RoleBinding(string Role, string? Resource = null, bool Inherit = true)
    {
        /// <summary>A bare role key becomes the plain (unscoped, inheritable) shape.</summary>
        /// <param name="roleKey">The <see cref="RoleSpec"/> key.</param>
        public static implicit operator RoleBinding(string roleKey) => new(roleKey);
    }
}

/// <summary>
/// Builds a <see cref="ManagementManifest"/>, checking back-references as they are made.
/// </summary>
/// <remarks>
/// The record form accepts a grant naming a role that does not exist; this does not. A
/// forward reference the builder lets through becomes a null dereference deep inside
/// <c>ApplyAsync</c>, <b>after</b> part of the tenant has already been written — so
/// every call that names an earlier key checks it, and <see cref="Build"/> reports every
/// problem at once rather than the first (&#167;27.6 rule 1).
/// </remarks>
public sealed class ManifestBuilder
{
    private readonly List<ManagementManifest.ResourceSpec> _resources = new();
    private readonly Dictionary<string, List<ManagementManifest.ScopeSpec>> _scopes = new(StringComparer.Ordinal);
    private readonly List<ManagementManifest.PermissionSpec> _permissions = new();
    private readonly List<ManagementManifest.RoleSpec> _roles = new();
    private readonly Dictionary<string, List<ManagementManifest.GrantSpec>> _grants = new(StringComparer.Ordinal);
    private readonly List<ManagementManifest.GroupSpec> _groups = new();
    private readonly Dictionary<string, List<ManagementManifest.RoleBinding>> _groupRoles = new(StringComparer.Ordinal);
    private readonly List<ManagementManifest.UserSpec> _users = new();
    private readonly Dictionary<string, List<ManagementManifest.RoleBinding>> _userRoles = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<string>> _userGroups = new(StringComparer.Ordinal);
    private readonly List<ManagementManifest.ServiceAccountSpec> _serviceAccounts = new();
    private readonly Dictionary<string, List<ManagementManifest.RoleBinding>> _serviceAccountRoles = new(StringComparer.Ordinal);
    private readonly List<ManagementManifest.NetworkSegmentSpec> _networkSegments = new();
    private readonly List<ManagementManifest.NetworkProfileSpec> _networkProfiles = new();
    private ManagementManifest.NetworkPolicySpec? _networkPolicy;
    private readonly List<string> _problems = new();

    /// <summary>Declares a root resource.</summary>
    /// <param name="key">Manifest-local identifier.</param>
    /// <param name="name">The resource's name.</param>
    /// <param name="resourceType">The resource's type.</param>
    /// <param name="metadata">An optional JSON object (&#167;27.6.1 item 1).</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder Resource(
        string key, string name, string resourceType, System.Text.Json.JsonElement? metadata = null)
    {
        _resources.Add(new ManagementManifest.ResourceSpec(key, name, resourceType, Metadata: metadata));
        return this;
    }

    /// <summary>Declares a resource beneath <paramref name="parentKey"/>.</summary>
    /// <param name="key">Manifest-local identifier.</param>
    /// <param name="name">The resource's name.</param>
    /// <param name="resourceType">The resource's type.</param>
    /// <param name="parentKey">The key of an already-declared resource.</param>
    /// <param name="metadata">An optional JSON object (&#167;27.6.1 item 1).</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder ChildResource(
        string key, string name, string resourceType, string parentKey,
        System.Text.Json.JsonElement? metadata = null)
    {
        if (!_resources.Any(r => r.Key == parentKey))
        {
            _problems.Add($"ChildResource '{key}' names parent '{parentKey}', " +
                          "which no Resource(...) call has declared yet");
            return this;
        }

        _resources.Add(new ManagementManifest.ResourceSpec(key, name, resourceType, parentKey, Metadata: metadata));
        return this;
    }

    /// <summary>Declares a scope beneath <paramref name="resourceKey"/>.</summary>
    /// <param name="resourceKey">The resource this scope belongs to.</param>
    /// <param name="key">Manifest-local identifier.</param>
    /// <param name="name">The scope's name.</param>
    /// <param name="description">What the scope is for.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder Scope(string resourceKey, string key, string name, string description)
    {
        if (!_resources.Any(r => r.Key == resourceKey))
        {
            _problems.Add($"Scope '{key}' names resource '{resourceKey}', " +
                          "which no Resource(...) call has declared yet");
            return this;
        }

        Add(_scopes, resourceKey, new ManagementManifest.ScopeSpec(key, name, description));
        return this;
    }

    /// <summary>Declares a permission.</summary>
    /// <param name="key">Manifest-local identifier.</param>
    /// <param name="action">The action it allows.</param>
    /// <param name="description">What it is for.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder Permission(string key, string action, string description)
    {
        _permissions.Add(new ManagementManifest.PermissionSpec(key, action, description));
        return this;
    }

    /// <summary>Declares a role.</summary>
    /// <param name="key">Manifest-local identifier.</param>
    /// <param name="name">The role's name.</param>
    /// <param name="description">What it is for.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder Role(string key, string name, string description)
    {
        _roles.Add(new ManagementManifest.RoleSpec(key, name, description));
        return this;
    }

    /// <summary>Declares a role that applies across every resource.</summary>
    /// <param name="key">Manifest-local identifier.</param>
    /// <param name="name">The role's name.</param>
    /// <param name="description">What it is for.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder GlobalRole(string key, string name, string description)
    {
        _roles.Add(new ManagementManifest.RoleSpec(key, name, description, Global: true));
        return this;
    }

    /// <summary>Grants a permission to the role named by <paramref name="roleKey"/>.</summary>
    /// <param name="roleKey">The role receiving the grant.</param>
    /// <param name="permissionKey">The permission being granted.</param>
    /// <param name="effect"><c>"allow"</c>, <c>"deny"</c>, or <c>null</c>.</param>
    /// <param name="scopeKeys">The scopes this grant is narrowed to.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder Grant(
        string roleKey, string permissionKey, string? effect = null, params string[] scopeKeys)
    {
        if (!_roles.Any(r => r.Key == roleKey))
        {
            _problems.Add($"Grant of '{permissionKey}' names role '{roleKey}', " +
                          "which no Role(...) call has declared yet");
            return this;
        }

        Add(_grants, roleKey, new ManagementManifest.GrantSpec(permissionKey, effect, scopeKeys));
        return this;
    }

    /// <summary>Declares a group, optionally holding roles (the plain, unscoped shape —
    /// use <see cref="GroupRole"/> for a resource-scoped or <c>inherit: false</c> one).</summary>
    /// <param name="key">Manifest-local identifier.</param>
    /// <param name="name">The group's name.</param>
    /// <param name="description">What it is for.</param>
    /// <param name="roleKeys">The roles this group should hold.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder Group(string key, string name, string description, params string[] roleKeys)
    {
        _groups.Add(new ManagementManifest.GroupSpec(key, name, description));
        foreach (string role in roleKeys)
        {
            Add(_groupRoles, key, role);
        }

        return this;
    }

    /// <summary>
    /// Binds a role to the group named by <paramref name="groupKey"/> (CONTRACT.md
    /// &#167;27.6.1 item 2, contract 1.51) — the general form, for a resource-scoped or
    /// <c>inherit: false</c> binding; <see cref="Group"/>'s trailing <c>roleKeys</c> is
    /// the shorthand for the plain shape.
    /// </summary>
    /// <param name="groupKey">The group receiving the binding.</param>
    /// <param name="roleKey">The role being bound.</param>
    /// <param name="resourceKey">The resource this binding is scoped to, or <c>null</c>
    /// for a plain (unscoped) binding.</param>
    /// <param name="inherit">Whether the binding also reaches the descendants of
    /// <paramref name="resourceKey"/>. Defaults to <c>true</c>.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder GroupRole(string groupKey, string roleKey, string? resourceKey = null, bool inherit = true)
    {
        if (!_groups.Any(g => g.Key == groupKey))
        {
            _problems.Add($"GroupRole names group '{groupKey}', " +
                          "which no Group(...) call has declared yet");
            return this;
        }

        Add(_groupRoles, groupKey, new ManagementManifest.RoleBinding(roleKey, resourceKey, inherit));
        return this;
    }

    /// <summary>Declares a user.</summary>
    /// <param name="key">Manifest-local identifier.</param>
    /// <param name="username">The user's username.</param>
    /// <param name="email">The user's email address.</param>
    /// <param name="initialPassword">The password to CREATE the user with.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder User(
        string key, string username, string email, Sensitive<string>? initialPassword = null)
    {
        _users.Add(new ManagementManifest.UserSpec(key, username, email, initialPassword));
        return this;
    }

    /// <summary>
    /// Binds a role to the user named by <paramref name="userKey"/>. Omit
    /// <paramref name="resourceKey"/> for the plain (unscoped) shape every SDK had before
    /// contract 1.51; supply it (with an optional <paramref name="inherit"/>) for the
    /// &#167;27.6.1 item 2 resource-scoped shape.
    /// </summary>
    /// <param name="userKey">The user receiving the role.</param>
    /// <param name="roleKey">The role being assigned.</param>
    /// <param name="resourceKey">The resource this binding is scoped to, or <c>null</c>
    /// for a plain (unscoped) binding.</param>
    /// <param name="inherit">Whether the binding also reaches the descendants of
    /// <paramref name="resourceKey"/>. Defaults to <c>true</c>.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder AssignRole(string userKey, string roleKey, string? resourceKey = null, bool inherit = true)
    {
        if (!_users.Any(u => u.Key == userKey))
        {
            _problems.Add($"AssignRole names user '{userKey}', " +
                          "which no User(...) call has declared yet");
            return this;
        }

        Add(_userRoles, userKey, new ManagementManifest.RoleBinding(roleKey, resourceKey, inherit));
        return this;
    }

    /// <summary>Puts a user into the group named by <paramref name="groupKey"/>.</summary>
    /// <param name="userKey">The user joining the group.</param>
    /// <param name="groupKey">The group being joined.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder AddToGroup(string userKey, string groupKey)
    {
        if (!_users.Any(u => u.Key == userKey))
        {
            _problems.Add($"AddToGroup names user '{userKey}', " +
                          "which no User(...) call has declared yet");
            return this;
        }

        Add(_userGroups, userKey, groupKey);
        return this;
    }

    /// <summary>
    /// Declares a service account (CONTRACT.md &#167;27.6.1 item 3, contract 1.51).
    /// </summary>
    /// <param name="key">Manifest-local identifier.</param>
    /// <param name="name">The account's name — the natural key reconciliation matches
    /// by. Not server-enforced unique; an ambiguous match fails before any write.</param>
    /// <param name="description">What the account is for.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder ServiceAccount(string key, string name, string? description = null)
    {
        _serviceAccounts.Add(new ManagementManifest.ServiceAccountSpec(key, name, description));
        return this;
    }

    /// <summary>Binds a role to the service account named by <paramref name="serviceAccountKey"/>.
    /// Same plain/resource-scoped shapes as <see cref="AssignRole"/>.</summary>
    /// <param name="serviceAccountKey">The service account receiving the role.</param>
    /// <param name="roleKey">The role being bound.</param>
    /// <param name="resourceKey">The resource this binding is scoped to, or <c>null</c>
    /// for a plain (unscoped) binding.</param>
    /// <param name="inherit">Whether the binding also reaches the descendants of
    /// <paramref name="resourceKey"/>. Defaults to <c>true</c>.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder AssignServiceAccountRole(
        string serviceAccountKey, string roleKey, string? resourceKey = null, bool inherit = true)
    {
        if (!_serviceAccounts.Any(a => a.Key == serviceAccountKey))
        {
            _problems.Add($"AssignServiceAccountRole names service account '{serviceAccountKey}', " +
                          "which no ServiceAccount(...) call has declared yet");
            return this;
        }

        Add(_serviceAccountRoles, serviceAccountKey, new ManagementManifest.RoleBinding(roleKey, resourceKey, inherit));
        return this;
    }

    /// <summary>
    /// Declares a network segment (CONTRACT.md &#167;27.6.2, contract 1.62).
    /// </summary>
    /// <param name="key">Manifest-local identifier.</param>
    /// <param name="site">The wire <c>site_key</c>.</param>
    /// <param name="kind"><see cref="NetworkSegmentKind.Access"/> or <see cref="NetworkSegmentKind.Quarantine"/>.</param>
    /// <param name="name">The segment's name.</param>
    /// <param name="vlanId">The segment's VLAN.</param>
    /// <param name="rank">The access segment's placement rank; <see cref="JsonNullable{T}.Null"/> states "none".</param>
    /// <param name="filterIds">The segment's <c>Filter-Id</c> envelope (compared as a set).</param>
    /// <param name="enabled">Whether the segment is a placement candidate.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder NetworkSegment(
        string key, string site, NetworkSegmentKind kind, string name, int vlanId,
        JsonNullable<int>? rank = null, IReadOnlyList<string>? filterIds = null, bool? enabled = null)
    {
        _networkSegments.Add(new ManagementManifest.NetworkSegmentSpec(
            key, site, kind, name, vlanId, rank, filterIds, enabled));
        return this;
    }

    /// <summary>
    /// Declares the reply profile of a segment declared earlier (CONTRACT.md &#167;27.6.2, contract 1.62).
    /// </summary>
    /// <param name="segmentKey">The key of an already-declared <see cref="NetworkSegment"/>.</param>
    /// <param name="sessionTimeoutSecs">The <c>Session-Timeout</c> in seconds.</param>
    /// <param name="terminationAction">The <c>Termination-Action</c>, or <c>null</c> when unstated.</param>
    /// <param name="idleTimeoutSecs">The <c>Idle-Timeout</c>; <see cref="JsonNullable{T}.Null"/> states "none".</param>
    /// <param name="filterId">One of the segment's <c>filter_ids</c>; <see cref="JsonNullable{T}.Null"/> states "none".</param>
    /// <param name="serviceType">The <c>Service-Type</c>; <see cref="JsonNullable{T}.Null"/> states "none".</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder NetworkProfile(
        string segmentKey, int sessionTimeoutSecs, RadiusTerminationAction? terminationAction = null,
        JsonNullable<int>? idleTimeoutSecs = null, JsonNullable<string>? filterId = null,
        JsonNullable<RadiusServiceType>? serviceType = null)
    {
        if (!_networkSegments.Any(g => g.Key == segmentKey))
        {
            _problems.Add($"NetworkProfile names segment '{segmentKey}', " +
                          "which no NetworkSegment(...) call has declared yet");
            return this;
        }

        _networkProfiles.Add(new ManagementManifest.NetworkProfileSpec(
            segmentKey, sessionTimeoutSecs, terminationAction, idleTimeoutSecs, filterId, serviceType));
        return this;
    }

    /// <summary>
    /// States the tenant's <c>Session-Timeout</c> cap (CONTRACT.md &#167;27.6.2, contract 1.62). A
    /// singleton: stating it twice is a problem <see cref="Build"/> reports.
    /// </summary>
    /// <param name="sessionTimeoutMaxSecs">The cap in seconds.</param>
    /// <returns>This builder.</returns>
    public ManifestBuilder NetworkPolicy(int sessionTimeoutMaxSecs)
    {
        if (_networkPolicy is not null)
        {
            _problems.Add("NetworkPolicy is stated more than once; the tenant has exactly one, " +
                          "so a manifest carries at most one");
            return this;
        }

        _networkPolicy = new ManagementManifest.NetworkPolicySpec(sessionTimeoutMaxSecs);
        return this;
    }

    /// <summary>Assembles the manifest, or throws if any back-reference is dangling.</summary>
    /// <returns>The assembled manifest.</returns>
    /// <exception cref="NetworkError">
    /// If any call named a key that was never declared.
    /// </exception>
    public ManagementManifest Build()
    {
        if (_problems.Count > 0)
        {
            throw NetworkError.FromMessage(
                "this manifest cannot be built:\n  - " + string.Join("\n  - ", _problems) +
                "\n\nEvery problem is listed rather than only the first: fixing them one " +
                "build at a time is the slowest possible way to learn about six of them.");
        }

        return new ManagementManifest
        {
            Resources = _resources
                .Select(r => r with { Scopes = Get(_scopes, r.Key) })
                .ToList(),
            Permissions = _permissions.ToList(),
            Roles = _roles.Select(r => r with { Grants = Get(_grants, r.Key) }).ToList(),
            Groups = _groups.Select(g => g with { Roles = Get(_groupRoles, g.Key) }).ToList(),
            Users = _users
                .Select(u => u with
                {
                    Roles = Get(_userRoles, u.Key),
                    Groups = Get(_userGroups, u.Key),
                })
                .ToList(),
            ServiceAccounts = _serviceAccounts
                .Select(a => a with { Roles = Get(_serviceAccountRoles, a.Key) })
                .ToList(),
            NetworkPolicy = _networkPolicy,
            NetworkSegments = _networkSegments.ToList(),
            NetworkProfiles = _networkProfiles.ToList(),
        };
    }

    private static void Add<T>(Dictionary<string, List<T>> map, string key, T value)
    {
        if (!map.TryGetValue(key, out List<T>? list))
        {
            list = new List<T>();
            map[key] = list;
        }

        list.Add(value);
    }

    private static IReadOnlyList<T> Get<T>(Dictionary<string, List<T>> map, string key)
        => map.TryGetValue(key, out List<T>? list) ? list : Array.Empty<T>();
}
