using Axiam.Sdk.Core;
using Axiam.Sdk.Management.Models;

namespace Axiam.Sdk.Management;

/// <summary>
/// The CONTRACT.md &#167;27.6 declarative layer: describe the tenant you want, then
/// reconcile toward it.
/// </summary>
/// <remarks>
/// <para>
/// Two operations, and the difference between them is the whole design.
/// <see cref="PlanAsync"/> issues reads and nothing else, so it can be run against
/// production to find out what an <see cref="ApplyAsync"/> would do.
/// <see cref="ApplyAsync"/> performs the writes, stops at the first failure, and does
/// not roll back.
/// </para>
/// <para>
/// A view over the management API, not a connection: constructing one performs no I/O
/// (&#167;27.2 rule 1).
/// </para>
/// </remarks>
public sealed class ManifestApi
{
    private static readonly PageRequest PlanPage = PageRequest.Of(200);

    private readonly ManagementApi _api;

    internal ManifestApi(ManagementApi api)
    {
        _api = api;
    }

    private enum Kind
    {
        Noop,
        CreateResource, UpdateResource, CreateScope,
        CreatePermission, UpdatePermission,
        CreateRole, UpdateRole, GrantPermission,
        CreateGroup, UpdateGroup, AssignRoleToGroup, UpdateRoleOnGroup,
        CreateUser, UpdateUser, AssignRoleToUser, UpdateRoleOnUser, AddGroupMember,
        CreateServiceAccount, UpdateServiceAccount, AssignRoleToServiceAccount, UpdateRoleOnServiceAccount,
    }

    /// <summary>Which server API a <see cref="Kind.AssignRoleToGroup"/>-family step targets —
    /// shared plumbing for the three subject kinds a &#167;27.6.1 role binding can bind to.</summary>
    private enum SubjectKind { Group, User, ServiceAccount }

    private sealed record Step(PlannedAction Action, Kind Kind, string Key, object? Spec, string? Related);

    /// <summary>
    /// A subject's CURRENT role binding, as the &#167;27 subject-side listing
    /// (<c>RoleAssignment</c>) reports it — used to reconcile against a manifest
    /// <see cref="ManagementManifest.RoleBinding"/> by its natural key, the role alone.
    /// </summary>
    private sealed record CurrentBinding(Guid RoleId, Guid? ResourceId, bool Inherit, IReadOnlyList<Guid>? TenantScope);

    /// <summary>The <c>Spec</c> of an <c>UpdateRoleOn*</c> step: what the manifest wants,
    /// paired with what the server currently holds (needed to unassign it, and to
    /// restore it if the assign half fails — CONTRACT.md &#167;27.6.1 item 2).</summary>
    private sealed record RebindSpec(ManagementManifest.RoleBinding Wanted, CurrentBinding Current);

    private sealed class Snapshot
    {
        internal IReadOnlyList<Resource> Resources { get; set; } = Array.Empty<Resource>();
        internal IReadOnlyList<Permission> Permissions { get; set; } = Array.Empty<Permission>();
        internal IReadOnlyList<Role> Roles { get; set; } = Array.Empty<Role>();
        internal IReadOnlyList<Group> Groups { get; set; } = Array.Empty<Group>();
        internal IReadOnlyList<UserResponse> Users { get; set; } = Array.Empty<UserResponse>();
        internal IReadOnlyList<ServiceAccountResponse> ServiceAccounts { get; set; } = Array.Empty<ServiceAccountResponse>();
        internal Dictionary<Guid, IReadOnlyList<Scope>> Scopes { get; } = new();
        internal Dictionary<Guid, IReadOnlyList<Guid>> RoleGrants { get; } = new();
        internal Dictionary<Guid, IReadOnlyList<CurrentBinding>> GroupRoleBindings { get; } = new();
        internal Dictionary<Guid, IReadOnlyList<CurrentBinding>> UserRoleBindings { get; } = new();
        internal Dictionary<Guid, IReadOnlyList<CurrentBinding>> ServiceAccountRoleBindings { get; } = new();
        internal Dictionary<Guid, IReadOnlyList<Guid>> GroupMembers { get; } = new();
    }

    private sealed class Resolved
    {
        internal Dictionary<string, Guid> Resources { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, Guid> Scopes { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, Guid> Permissions { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, Guid> Roles { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, Guid> Groups { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, Guid> Users { get; } = new(StringComparer.Ordinal);
        internal Dictionary<string, Guid> ServiceAccounts { get; } = new(StringComparer.Ordinal);

        /// <summary>§27.5 rule 5: the one-time <c>client_secret</c> response of every
        /// service account this apply created, keyed by manifest key — read back by
        /// <see cref="ExecuteAsync"/> to attach to that step's <see cref="StepOutcome"/>.</summary>
        internal Dictionary<string, ServiceAccountCreatedResponse> CreatedServiceAccounts { get; } = new(StringComparer.Ordinal);
    }

    /// <summary>
    /// CONTRACT.md &#167;27.6.1 item 2 (contract 1.51): thrown by <see cref="RunAsync"/>
    /// when a role-binding UPDATE's assign half fails after its unassign half already
    /// succeeded — carries whether the restore (re-assigning the previous binding)
    /// succeeded, so <see cref="ExecuteAsync"/> can attach it to the step's outcome.
    /// </summary>
    private sealed class BindingUpdateFailedException : NetworkError
    {
        internal bool RestoreSucceeded { get; }

        /// <summary>
        /// N6.3 (CONTRACT 1.52, C-12): the restore's own error, when the restore itself
        /// also failed — <c>null</c> when <see cref="RestoreSucceeded"/> is <c>true</c>.
        /// </summary>
        internal string? RestoreError { get; }

        internal BindingUpdateFailedException(string message, bool restoreSucceeded, string? restoreError = null)
            : base(message, null)
        {
            RestoreSucceeded = restoreSucceeded;
            RestoreError = restoreError;
        }
    }

    /// <summary>
    /// Reports what reconciling <paramref name="manifest"/> would change, writing nothing.
    /// </summary>
    /// <remarks>
    /// Every request this issues is a read (&#167;27.6 rule 1), and the plan is stable:
    /// running it twice against an unchanged tenant produces the same actions in the
    /// same order.
    /// </remarks>
    /// <param name="manifest">The tenant description to compare against.</param>
    /// <param name="cancellationToken">Cancels the reads.</param>
    /// <returns>The plan, including the steps that would change nothing.</returns>
    public async Task<ManagementPlan> PlanAsync(
        ManagementManifest manifest, CancellationToken cancellationToken = default)
    {
        ManifestValidation.Validate(manifest);
        Snapshot snapshot = await ReadAsync(manifest, cancellationToken).ConfigureAwait(false);
        RequireUnambiguousServiceAccountNames(manifest, snapshot);
        List<Step> steps = Derive(manifest, snapshot, new Resolved());
        return new ManagementPlan(steps.Select(s => s.Action).ToList());
    }

    /// <summary>
    /// Reconciles the tenant toward <paramref name="manifest"/>.
    /// </summary>
    /// <remarks>
    /// Stops at the first failure and does <b>not</b> roll back (&#167;27.6 rule 7):
    /// everything before the failure stands, and everything after it is reported as
    /// <see cref="ApplyStatus.NotAttempted"/>.
    /// </remarks>
    /// <param name="manifest">The tenant description to converge on.</param>
    /// <param name="cancellationToken">Cancels the reconciliation.</param>
    /// <returns>What every step did.</returns>
    public async Task<ApplyReport> ApplyAsync(
        ManagementManifest manifest, CancellationToken cancellationToken = default)
    {
        ManifestValidation.Validate(manifest);
        var resolved = new Resolved();
        Snapshot snapshot = await ReadAsync(manifest, cancellationToken).ConfigureAwait(false);
        RequireUnambiguousServiceAccountNames(manifest, snapshot);
        List<Step> steps = Derive(manifest, snapshot, resolved);
        RequirePasswords(steps);
        return await ExecuteAsync(steps, resolved, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Snapshot> ReadAsync(ManagementManifest manifest, CancellationToken token)
    {
        var snapshot = new Snapshot
        {
            Resources = await _api.Resources.ListAllAsync(start: PlanPage, cancellationToken: token).ConfigureAwait(false),
            Permissions = await _api.Permissions.ListAllAsync(start: PlanPage, cancellationToken: token).ConfigureAwait(false),
            Roles = await _api.Roles.ListAllAsync(start: PlanPage, cancellationToken: token).ConfigureAwait(false),
            Groups = await _api.Groups.ListAllAsync(start: PlanPage, cancellationToken: token).ConfigureAwait(false),
            Users = await _api.Users.ListAllAsync(start: PlanPage, cancellationToken: token).ConfigureAwait(false),
            // Read only when the manifest names a service account, so a manifest without
            // one makes no new request (§27.6.1 item 3).
            ServiceAccounts = manifest.ServiceAccounts.Count > 0
                ? await _api.ServiceAccounts.ListAllAsync(start: PlanPage, cancellationToken: token).ConfigureAwait(false)
                : Array.Empty<ServiceAccountResponse>(),
        };

        // Only the resources, roles and groups the manifest could match: a tenant with a
        // thousand resources should not cost a thousand scope reads to plan five.
        var wantedResources = manifest.Resources.Select(r => r.Name).ToHashSet(StringComparer.Ordinal);
        foreach (Resource resource in snapshot.Resources.Where(r => wantedResources.Contains(r.Name)))
        {
            snapshot.Scopes[resource.Id] =
                await _api.Scopes.ListAsync(resource.Id, token).ConfigureAwait(false);
        }

        var wantedRoles = manifest.Roles.Select(r => r.Name).ToHashSet(StringComparer.Ordinal);
        foreach (Role role in snapshot.Roles.Where(r => wantedRoles.Contains(r.Name)))
        {
            snapshot.RoleGrants[role.Id] = (await _api.Roles.ListPermissionsAsync(role.Id, token)
                .ConfigureAwait(false)).Select(g => g.Permission.Id).ToList();
        }

        var wantedGroups = manifest.Groups.Select(g => g.Name).ToHashSet(StringComparer.Ordinal);
        // Only a group whose manifest spec actually STATES roles costs a role-binding
        // read — a manifest section that never mentions roles for a subject makes no new
        // request for them, the same "only what could match" discipline the resource/
        // role/group reads above already apply.
        var groupsWithRoles = manifest.Groups.Where(g => (g.Roles?.Count ?? 0) > 0)
            .Select(g => g.Name).ToHashSet(StringComparer.Ordinal);
        foreach (Group group in snapshot.Groups.Where(g => wantedGroups.Contains(g.Name)))
        {
            snapshot.GroupMembers[group.Id] = (await _api.Groups
                .ListMembersAllAsync(group.Id, start: PlanPage, cancellationToken: token)
                .ConfigureAwait(false)).Select(u => u.Id).ToList();
            if (groupsWithRoles.Contains(group.Name))
            {
                snapshot.GroupRoleBindings[group.Id] = ToCurrentBindings(
                    await _api.Groups.ListRolesAsync(group.Id, token).ConfigureAwait(false));
            }
        }

        var wantedUsers = manifest.Users.Select(u => u.Username).ToHashSet(StringComparer.Ordinal);
        var usersWithRoles = manifest.Users.Where(u => (u.Roles?.Count ?? 0) > 0)
            .Select(u => u.Username).ToHashSet(StringComparer.Ordinal);
        foreach (UserResponse user in snapshot.Users.Where(u => wantedUsers.Contains(u.Username)))
        {
            if (usersWithRoles.Contains(user.Username))
            {
                snapshot.UserRoleBindings[user.Id] = ToCurrentBindings(
                    await _api.Users.ListRolesAsync(user.Id, token).ConfigureAwait(false));
            }
        }

        var wantedServiceAccounts = manifest.ServiceAccounts.Select(a => a.Name).ToHashSet(StringComparer.Ordinal);
        var serviceAccountsWithRoles = manifest.ServiceAccounts.Where(a => (a.Roles?.Count ?? 0) > 0)
            .Select(a => a.Name).ToHashSet(StringComparer.Ordinal);
        foreach (ServiceAccountResponse account in snapshot.ServiceAccounts.Where(a => wantedServiceAccounts.Contains(a.Name)))
        {
            if (serviceAccountsWithRoles.Contains(account.Name))
            {
                snapshot.ServiceAccountRoleBindings[account.Id] = ToCurrentBindings(
                    await _api.ServiceAccounts.ListRolesAsync(account.Id, token).ConfigureAwait(false));
            }
        }

        return snapshot;
    }

    private static IReadOnlyList<CurrentBinding> ToCurrentBindings(IReadOnlyList<RoleAssignment> assignments) =>
        assignments.Select(a => new CurrentBinding(a.Role.Id, a.ResourceId, a.Inherit, a.TenantScope)).ToList();

    /// <summary>
    /// §27.6.1 item 3: a stated service-account name matching more than one EXISTING
    /// account fails PlanAsync/ApplyAsync before any write — picking one would reconcile
    /// an arbitrary account, since the server does not keep names unique.
    /// </summary>
    private static void RequireUnambiguousServiceAccountNames(ManagementManifest manifest, Snapshot snapshot)
    {
        var ambiguous = manifest.ServiceAccounts
            .Select(a => a.Name)
            .Distinct(StringComparer.Ordinal)
            .Where(name => snapshot.ServiceAccounts.Count(a => a.Name == name) > 1)
            .ToList();
        if (ambiguous.Count > 0)
        {
            throw NetworkError.FromMessage(
                "this manifest cannot be reconciled:\n  - " + string.Join("\n  - ", ambiguous.Select(
                    name => $"service account name '{name}' matches more than one existing account; " +
                            "the server does not enforce names unique, so reconciling by name would pick one arbitrarily")) +
                "\n\nNothing was sent: §27.6 rule 1 refuses a manifest before the first request " +
                "rather than part-way through an apply.");
        }
    }

    private static List<Step> Derive(ManagementManifest m, Snapshot snap, Resolved res)
    {
        var outSteps = new List<Step>();
        Dictionary<string, ManagementManifest.ResourceSpec> specs = m.Resources
            .GroupBy(r => r.Key, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);

        foreach (string key in ManifestValidation.TopologicalOrder(m))
        {
            ManagementManifest.ResourceSpec spec = specs[key];
            bool parentPending = spec.Parent is not null && !res.Resources.ContainsKey(spec.Parent);
            Guid? parentId = spec.Parent is { } p && res.Resources.TryGetValue(p, out Guid pid)
                ? pid
                : null;
            // A child whose parent is itself pending cannot already exist, so matching it
            // against a root of the same name would be wrong.
            Resource? existing = parentPending
                ? null
                : snap.Resources.FirstOrDefault(r => r.Name == spec.Name && r.ParentId == parentId);
            string summary = $"resource '{spec.Name}' ({spec.ResourceType})";
            if (existing is not null)
            {
                res.Resources[key] = existing.Id;
                // §27.6.1 item 1: JSON value equality of the WHOLE object, never a
                // key-by-key merge — and only when the manifest STATES metadata at all
                // (rule 3's silence-means-unstated). A stated {} matches what the server
                // returns for none (an empty object, never absent, per the model).
                bool metadataDrifted = spec.Metadata is { } wanted
                    && !JsonElementDeepEquals(wanted, existing.Metadata);
                bool drifted = existing.ResourceType != spec.ResourceType || metadataDrifted;
                outSteps.Add(MakeStep(
                    drifted ? PlanChange.Update : PlanChange.NoChange, PlanTarget.Resource, key,
                    summary, drifted ? Kind.UpdateResource : Kind.Noop, spec, null));
            }
            else
            {
                outSteps.Add(MakeStep(PlanChange.Create, PlanTarget.Resource, key, summary,
                    Kind.CreateResource, spec, null));
            }
        }

        foreach (ManagementManifest.ResourceSpec spec in m.Resources)
        {
            IReadOnlyList<Scope> current =
                res.Resources.TryGetValue(spec.Key, out Guid rid) &&
                snap.Scopes.TryGetValue(rid, out IReadOnlyList<Scope>? found)
                    ? found
                    : Array.Empty<Scope>();
            foreach (ManagementManifest.ScopeSpec scope in
                     spec.Scopes ?? Array.Empty<ManagementManifest.ScopeSpec>())
            {
                string summary = $"scope '{scope.Name}' under resource '{spec.Name}'";
                Scope? match = current.FirstOrDefault(s => s.Name == scope.Name);
                if (match is not null)
                {
                    res.Scopes[scope.Key] = match.Id;
                    outSteps.Add(MakeStep(PlanChange.NoChange, PlanTarget.Scope, scope.Key,
                        summary, Kind.Noop, scope, spec.Key));
                }
                else
                {
                    outSteps.Add(MakeStep(PlanChange.Create, PlanTarget.Scope, scope.Key,
                        summary, Kind.CreateScope, scope, spec.Key));
                }
            }
        }

        foreach (ManagementManifest.PermissionSpec spec in m.Permissions)
        {
            string summary = $"permission '{spec.Action}'";
            Permission? found = snap.Permissions.FirstOrDefault(p => p.Action == spec.Action);
            if (found is not null)
            {
                res.Permissions[spec.Key] = found.Id;
                bool drifted = found.Description != spec.Description;
                outSteps.Add(MakeStep(
                    drifted ? PlanChange.Update : PlanChange.NoChange, PlanTarget.Permission,
                    spec.Key, summary, drifted ? Kind.UpdatePermission : Kind.Noop, spec, null));
            }
            else
            {
                outSteps.Add(MakeStep(PlanChange.Create, PlanTarget.Permission, spec.Key, summary,
                    Kind.CreatePermission, spec, null));
            }
        }

        foreach (ManagementManifest.RoleSpec spec in m.Roles)
        {
            string summary = $"role '{spec.Name}'";
            Role? found = snap.Roles.FirstOrDefault(r => r.Name == spec.Name);
            if (found is not null)
            {
                res.Roles[spec.Key] = found.Id;
                bool drifted = found.Description != spec.Description || found.IsGlobal != spec.Global;
                outSteps.Add(MakeStep(
                    drifted ? PlanChange.Update : PlanChange.NoChange, PlanTarget.Role, spec.Key,
                    summary, drifted ? Kind.UpdateRole : Kind.Noop, spec, null));
            }
            else
            {
                outSteps.Add(MakeStep(PlanChange.Create, PlanTarget.Role, spec.Key, summary,
                    Kind.CreateRole, spec, null));
            }
        }

        foreach (ManagementManifest.RoleSpec role in m.Roles)
        {
            IReadOnlyList<Guid> granted =
                res.Roles.TryGetValue(role.Key, out Guid roleId) &&
                snap.RoleGrants.TryGetValue(roleId, out IReadOnlyList<Guid>? g)
                    ? g
                    : Array.Empty<Guid>();
            foreach (ManagementManifest.GrantSpec grant in
                     role.Grants ?? Array.Empty<ManagementManifest.GrantSpec>())
            {
                string summary = $"grant '{grant.Permission}' to role '{role.Name}'";
                bool already = res.Permissions.TryGetValue(grant.Permission, out Guid permissionId)
                               && granted.Contains(permissionId);
                outSteps.Add(MakeStep(
                    already ? PlanChange.NoChange : PlanChange.Create, PlanTarget.RoleGrant,
                    role.Key, summary, already ? Kind.Noop : Kind.GrantPermission, grant, role.Key));
            }
        }

        foreach (ManagementManifest.GroupSpec spec in m.Groups)
        {
            string summary = $"group '{spec.Name}'";
            Group? found = snap.Groups.FirstOrDefault(g => g.Name == spec.Name);
            if (found is not null)
            {
                res.Groups[spec.Key] = found.Id;
                bool drifted = found.Description != spec.Description;
                outSteps.Add(MakeStep(
                    drifted ? PlanChange.Update : PlanChange.NoChange, PlanTarget.Group, spec.Key,
                    summary, drifted ? Kind.UpdateGroup : Kind.Noop, spec, null));
            }
            else
            {
                outSteps.Add(MakeStep(PlanChange.Create, PlanTarget.Group, spec.Key, summary,
                    Kind.CreateGroup, spec, null));
            }
        }

        foreach (ManagementManifest.GroupSpec group in m.Groups)
        {
            IReadOnlyList<CurrentBinding> current =
                res.Groups.TryGetValue(group.Key, out Guid groupId) &&
                snap.GroupRoleBindings.TryGetValue(groupId, out IReadOnlyList<CurrentBinding>? found)
                    ? found
                    : Array.Empty<CurrentBinding>();
            DeriveRoleBindingSteps(
                outSteps, group.Roles, group.Key, $"group '{group.Name}'", current, res,
                PlanTarget.GroupRole, Kind.AssignRoleToGroup, Kind.UpdateRoleOnGroup);
        }

        foreach (ManagementManifest.UserSpec spec in m.Users)
        {
            string summary = $"user '{spec.Username}'";
            UserResponse? found = snap.Users.FirstOrDefault(u => u.Username == spec.Username);
            if (found is not null)
            {
                res.Users[spec.Key] = found.Id;
                bool drifted = found.Email != spec.Email;
                outSteps.Add(MakeStep(
                    drifted ? PlanChange.Update : PlanChange.NoChange, PlanTarget.User, spec.Key,
                    summary, drifted ? Kind.UpdateUser : Kind.Noop, spec, null));
            }
            else
            {
                outSteps.Add(MakeStep(PlanChange.Create, PlanTarget.User, spec.Key, summary,
                    Kind.CreateUser, spec, null));
            }
        }

        foreach (ManagementManifest.UserSpec user in m.Users)
        {
            IReadOnlyList<CurrentBinding> current =
                res.Users.TryGetValue(user.Key, out Guid userId) &&
                snap.UserRoleBindings.TryGetValue(userId, out IReadOnlyList<CurrentBinding>? found)
                    ? found
                    : Array.Empty<CurrentBinding>();
            DeriveRoleBindingSteps(
                outSteps, user.Roles, user.Key, $"user '{user.Username}'", current, res,
                PlanTarget.UserRole, Kind.AssignRoleToUser, Kind.UpdateRoleOnUser);
        }

        foreach (ManagementManifest.UserSpec user in m.Users)
        {
            foreach (string groupKey in user.Groups ?? Array.Empty<string>())
            {
                string summary = $"user '{user.Username}' in group '{groupKey}'";
                bool already = res.Groups.TryGetValue(groupKey, out Guid groupId) &&
                               res.Users.TryGetValue(user.Key, out Guid userId) &&
                               snap.GroupMembers.TryGetValue(groupId, out IReadOnlyList<Guid>? held) &&
                               held.Contains(userId);
                outSteps.Add(MakeStep(
                    already ? PlanChange.NoChange : PlanChange.Create, PlanTarget.GroupMember,
                    user.Key, summary, already ? Kind.Noop : Kind.AddGroupMember,
                    groupKey, user.Key));
            }
        }

        // §27.6 rule 5 / §27.6.1 item 3: service accounts and their role bindings are
        // ordered LAST — after every other namespace, including users.
        foreach (ManagementManifest.ServiceAccountSpec spec in m.ServiceAccounts)
        {
            string summary = $"service account '{spec.Name}'";
            ServiceAccountResponse? found = snap.ServiceAccounts.FirstOrDefault(a => a.Name == spec.Name);
            if (found is not null)
            {
                res.ServiceAccounts[spec.Key] = found.Id;
                // §27.6.1 item 3: description is the only field Update reconciles;
                // status is not a manifest field in contract 1.51.
                bool drifted = spec.Description is { } wanted && wanted != (found.Description ?? string.Empty);
                outSteps.Add(MakeStep(
                    drifted ? PlanChange.Update : PlanChange.NoChange, PlanTarget.ServiceAccount, spec.Key,
                    summary, drifted ? Kind.UpdateServiceAccount : Kind.Noop, spec, null));
            }
            else
            {
                outSteps.Add(MakeStep(PlanChange.Create, PlanTarget.ServiceAccount, spec.Key, summary,
                    Kind.CreateServiceAccount, spec, null));
            }
        }

        foreach (ManagementManifest.ServiceAccountSpec spec in m.ServiceAccounts)
        {
            IReadOnlyList<CurrentBinding> current =
                res.ServiceAccounts.TryGetValue(spec.Key, out Guid accountId) &&
                snap.ServiceAccountRoleBindings.TryGetValue(accountId, out IReadOnlyList<CurrentBinding>? found)
                    ? found
                    : Array.Empty<CurrentBinding>();
            DeriveRoleBindingSteps(
                outSteps, spec.Roles, spec.Key, $"service account '{spec.Name}'", current, res,
                PlanTarget.ServiceAccountRole, Kind.AssignRoleToServiceAccount, Kind.UpdateRoleOnServiceAccount);
        }

        return outSteps;
    }

    private static Step MakeStep(
        PlanChange change, PlanTarget target, string key, string summary,
        Kind kind, object? spec, string? related)
        => new(new PlannedAction(change, target, key, summary), kind, key, spec, related);

    /// <summary>
    /// CONTRACT.md &#167;27.6.1 item 2 (contract 1.51): reconciles one subject's
    /// &#167;27.6.1 role bindings — group, user or service account alike, which is why
    /// this is shared rather than written three times. Natural key is <c>Role</c> alone;
    /// <c>Resource</c>/<c>Inherit</c> are fields, so a binding that changed either is an
    /// UPDATE (unassign, then assign — there is no update endpoint), never a second
    /// create the server would refuse with 409.
    /// </summary>
    private static void DeriveRoleBindingSteps(
        List<Step> outSteps,
        IReadOnlyList<ManagementManifest.RoleBinding>? bindings,
        string subjectKey,
        string subjectLabel,
        IReadOnlyList<CurrentBinding> current,
        Resolved res,
        PlanTarget target,
        Kind assignKind,
        Kind updateKind)
    {
        foreach (ManagementManifest.RoleBinding binding in bindings ?? Array.Empty<ManagementManifest.RoleBinding>())
        {
            string scopeNote = binding.Resource is { } r ? $" at resource '{r}'" : string.Empty;
            string inheritNote = binding.Inherit ? string.Empty : ", inherit: false";
            string summary = $"role '{binding.Role}' on {subjectLabel}{scopeNote}{inheritNote}";

            // Every Role/Resource KEY is already guaranteed to resolve to a KNOWN
            // MANIFEST entry by ManifestValidation.Validate (run before Derive is ever
            // called) — but its SERVER id may not exist yet: PlanAsync/ApplyAsync are
            // computing this BEFORE the role (and/or resource) has necessarily been
            // created, when it is itself pending in this very run. Either dependency
            // being unresolved means the server cannot already hold this exact binding
            // (it cannot hold a binding to a role, or scoped to a resource, that does
            // not exist), so this is unconditionally a Create — never a lookup against
            // `current` with a placeholder id that could accidentally collide.
            if (!res.Roles.TryGetValue(binding.Role, out Guid roleId) ||
                (binding.Resource is { } pendingResource && !res.Resources.TryGetValue(pendingResource, out _)))
            {
                outSteps.Add(MakeStep(PlanChange.Create, target, subjectKey, summary, assignKind, binding, subjectKey));
                continue;
            }

            Guid? resourceId = binding.Resource is { } resKey ? res.Resources[resKey] : null;

            CurrentBinding? match = current.FirstOrDefault(c => c.RoleId == roleId);
            if (match is null)
            {
                outSteps.Add(MakeStep(PlanChange.Create, target, subjectKey, summary, assignKind, binding, subjectKey));
            }
            else if (match.ResourceId == resourceId && match.Inherit == binding.Inherit)
            {
                outSteps.Add(MakeStep(PlanChange.NoChange, target, subjectKey, summary, Kind.Noop, binding, subjectKey));
            }
            else
            {
                outSteps.Add(MakeStep(
                    PlanChange.Update, target, subjectKey, summary, updateKind,
                    new RebindSpec(binding, match), subjectKey));
            }
        }
    }

    /// <summary>
    /// §27.6.1 item 1: JSON value equality — order-independent for object members,
    /// order-SENSITIVE for array elements (RFC 8259 arrays are ordered; objects are not).
    /// Never a key-by-key merge: two objects with the same keys but different values are
    /// unequal, and so are two objects where one simply has an extra key.
    /// </summary>
    private static bool JsonElementDeepEquals(System.Text.Json.JsonElement a, System.Text.Json.JsonElement b)
    {
        if (a.ValueKind != b.ValueKind)
        {
            return false;
        }

        switch (a.ValueKind)
        {
            case System.Text.Json.JsonValueKind.Object:
                var aProps = a.EnumerateObject().ToDictionary(p => p.Name, p => p.Value, StringComparer.Ordinal);
                var bProps = b.EnumerateObject().ToDictionary(p => p.Name, p => p.Value, StringComparer.Ordinal);
                if (aProps.Count != bProps.Count)
                {
                    return false;
                }
                return aProps.All(kv => bProps.TryGetValue(kv.Key, out System.Text.Json.JsonElement bv)
                                          && JsonElementDeepEquals(kv.Value, bv));

            case System.Text.Json.JsonValueKind.Array:
                System.Text.Json.JsonElement[] aItems = a.EnumerateArray().ToArray();
                System.Text.Json.JsonElement[] bItems = b.EnumerateArray().ToArray();
                return aItems.Length == bItems.Length
                       && aItems.Zip(bItems, JsonElementDeepEquals).All(eq => eq);

            case System.Text.Json.JsonValueKind.String:
                return a.GetString() == b.GetString();

            case System.Text.Json.JsonValueKind.Number:
                // Raw text compare first (catches "1" vs "1.0" as the SAME server-round-tripped
                // value only when the bytes agree; falls back to numeric compare so 1 == 1.0).
                return a.GetRawText() == b.GetRawText() || a.GetDouble() == b.GetDouble();

            default: // True, False, Null, Undefined — ValueKind equality (checked above) is enough.
                return true;
        }
    }

    /// <summary>
    /// Refuses, before any request, when a user must be created with no password.
    /// </summary>
    private static void RequirePasswords(List<Step> steps)
    {
        List<string> missing = steps
            .Where(s => s.Kind == Kind.CreateUser)
            .Where(s => ((ManagementManifest.UserSpec)s.Spec!).InitialPassword is null)
            .Select(s => s.Key)
            .ToList();
        if (missing.Count > 0)
        {
            throw NetworkError.FromMessage(
                $"manifest would create {missing.Count} user(s) with no InitialPassword: " +
                $"[{string.Join(", ", missing)}]. A user cannot be created without one, and " +
                "this is refused before any request rather than part-way through an apply " +
                "(§27.6 rule 1).");
        }
    }

    private async Task<ApplyReport> ExecuteAsync(
        List<Step> steps, Resolved res, CancellationToken token)
    {
        var applied = new List<AppliedStep>();
        bool stopped = false;
        foreach (Step step in steps)
        {
            if (stopped)
            {
                applied.Add(new AppliedStep(step.Action, new StepOutcome(ApplyStatus.NotAttempted)));
                continue;
            }

            if (step.Kind == Kind.Noop)
            {
                applied.Add(new AppliedStep(step.Action, new StepOutcome(ApplyStatus.Unchanged)));
                continue;
            }

            try
            {
                await RunAsync(step, res, token).ConfigureAwait(false);
            }
            // The §2 taxonomy, and nothing wider: a step that failed because the server
            // refused it is a reportable outcome, but a bug in this SDK is not — letting
            // an ArgumentException land in a StepOutcome would report "the tenant is
            // part-reconciled" when the truth is "this code is wrong".
            catch (Exception ex) when (ex is AuthError or AuthzError or NetworkError)
            {
                // §27.6.1 item 2: a role-binding rebind's assign half failing carries
                // whether the restore of the previous binding succeeded.
                StepOutcome outcome = ex is BindingUpdateFailedException rebindFailure
                    ? new StepOutcome(
                        ApplyStatus.Failed, ex.Message,
                        RestoreSucceeded: rebindFailure.RestoreSucceeded,
                        RestoreError: rebindFailure.RestoreError)
                    : new StepOutcome(ApplyStatus.Failed, ex.Message);
                applied.Add(new AppliedStep(step.Action, outcome));
                stopped = true;
                continue;
            }

            ApplyStatus status = step.Kind.ToString().StartsWith("Update", StringComparison.Ordinal)
                ? ApplyStatus.Updated
                : ApplyStatus.Created;
            // §27.5 rule 5: the one-time client_secret rides on THIS action's own
            // Created outcome, even when a later action of the same apply fails — kept
            // here rather than dropped because rule 3's "once" is literal.
            ServiceAccountCreatedResponse? createdServiceAccount =
                step.Kind == Kind.CreateServiceAccount && res.CreatedServiceAccounts.TryGetValue(step.Key, out var csa)
                    ? csa
                    : null;
            applied.Add(new AppliedStep(step.Action, new StepOutcome(status, CreatedServiceAccount: createdServiceAccount)));
        }

        return new ApplyReport(applied);
    }

    private async Task RunAsync(Step s, Resolved res, CancellationToken token)
    {
        switch (s.Kind)
        {
            case Kind.CreateResource:
            {
                var spec = (ManagementManifest.ResourceSpec)s.Spec!;
                Resource created = await _api.Resources.CreateAsync(
                    new CreateResourceRequest
                    {
                        Name = spec.Name,
                        ParentId = spec.Parent is { } p ? res.Resources[p] : null,
                        ResourceType = spec.ResourceType,
                        Metadata = spec.Metadata,
                    }, token).ConfigureAwait(false);
                res.Resources[s.Key] = created.Id;
                break;
            }

            case Kind.UpdateResource:
            {
                var spec = (ManagementManifest.ResourceSpec)s.Spec!;
                await _api.Resources.UpdateAsync(
                    res.Resources[s.Key],
                    new UpdateResourceRequest { ResourceType = spec.ResourceType, Metadata = spec.Metadata },
                    token).ConfigureAwait(false);
                break;
            }

            case Kind.CreateScope:
            {
                var spec = (ManagementManifest.ScopeSpec)s.Spec!;
                Scope created = await _api.Scopes.CreateAsync(
                    res.Resources[s.Related!],
                    new CreateScopeRequest { Description = spec.Description, Name = spec.Name },
                    token).ConfigureAwait(false);
                res.Scopes[s.Key] = created.Id;
                break;
            }

            case Kind.CreatePermission:
            {
                var spec = (ManagementManifest.PermissionSpec)s.Spec!;
                Permission created = await _api.Permissions.CreateAsync(
                    new CreatePermissionRequest { Action = spec.Action, Description = spec.Description },
                    token).ConfigureAwait(false);
                res.Permissions[s.Key] = created.Id;
                break;
            }

            case Kind.UpdatePermission:
            {
                var spec = (ManagementManifest.PermissionSpec)s.Spec!;
                await _api.Permissions.UpdateAsync(
                    res.Permissions[s.Key],
                    new UpdatePermissionRequest { Description = spec.Description }, token)
                    .ConfigureAwait(false);
                break;
            }

            case Kind.CreateRole:
            {
                var spec = (ManagementManifest.RoleSpec)s.Spec!;
                Role created = await _api.Roles.CreateAsync(
                    new CreateRoleRequest
                    {
                        Description = spec.Description,
                        IsGlobal = spec.Global,
                        Name = spec.Name,
                    }, token).ConfigureAwait(false);
                res.Roles[s.Key] = created.Id;
                break;
            }

            case Kind.UpdateRole:
            {
                var spec = (ManagementManifest.RoleSpec)s.Spec!;
                await _api.Roles.UpdateAsync(
                    res.Roles[s.Key],
                    new UpdateRole { Description = spec.Description, IsGlobal = spec.Global }, token)
                    .ConfigureAwait(false);
                break;
            }

            case Kind.GrantPermission:
            {
                var grant = (ManagementManifest.GrantSpec)s.Spec!;
                var scopeIds = (grant.Scopes ?? Array.Empty<string>())
                    .Where(res.Scopes.ContainsKey).Select(k => res.Scopes[k]).ToList();
                await _api.Roles.GrantPermissionAsync(
                    res.Roles[s.Related!],
                    new GrantPermissionRequest
                    {
                        Effect = grant.Effect is null
                            ? null
                            : grant.Effect == "deny" ? PermissionEffect.Deny : PermissionEffect.Allow,
                        PermissionId = res.Permissions[grant.Permission],
                        ScopeIds = scopeIds.Count > 0 ? scopeIds : null,
                    }, token).ConfigureAwait(false);
                break;
            }

            case Kind.CreateGroup:
            {
                var spec = (ManagementManifest.GroupSpec)s.Spec!;
                Group created = await _api.Groups.CreateAsync(
                    new CreateGroupRequest { Description = spec.Description, Name = spec.Name },
                    token).ConfigureAwait(false);
                res.Groups[s.Key] = created.Id;
                break;
            }

            case Kind.UpdateGroup:
            {
                var spec = (ManagementManifest.GroupSpec)s.Spec!;
                await _api.Groups.UpdateAsync(
                    res.Groups[s.Key], new UpdateGroup { Description = spec.Description }, token)
                    .ConfigureAwait(false);
                break;
            }

            case Kind.AssignRoleToGroup:
            {
                var binding = (ManagementManifest.RoleBinding)s.Spec!;
                await AssignAsync(SubjectKind.Group, res.Roles[binding.Role], res.Groups[s.Related!],
                    binding.Resource is { } r ? res.Resources[r] : null, binding.Inherit, tenantScope: null, token)
                    .ConfigureAwait(false);
                break;
            }

            case Kind.UpdateRoleOnGroup:
                await RebindAsync(SubjectKind.Group, res.Groups[s.Related!], (RebindSpec)s.Spec!, res, token).ConfigureAwait(false);
                break;

            case Kind.CreateUser:
            {
                var spec = (ManagementManifest.UserSpec)s.Spec!;
                UserResponse created = await _api.Users.CreateAsync(
                    new CreateUserRequest
                    {
                        Email = spec.Email,
                        Password = spec.InitialPassword!.Value,
                        Username = spec.Username,
                    }, token).ConfigureAwait(false);
                res.Users[s.Key] = created.Id;
                break;
            }

            case Kind.UpdateUser:
            {
                var spec = (ManagementManifest.UserSpec)s.Spec!;
                await _api.Users.UpdateAsync(
                    res.Users[s.Key], new UpdateUserRequest { Email = spec.Email }, token)
                    .ConfigureAwait(false);
                break;
            }

            case Kind.AssignRoleToUser:
            {
                var binding = (ManagementManifest.RoleBinding)s.Spec!;
                await AssignAsync(SubjectKind.User, res.Roles[binding.Role], res.Users[s.Related!],
                    binding.Resource is { } r ? res.Resources[r] : null, binding.Inherit, tenantScope: null, token)
                    .ConfigureAwait(false);
                break;
            }

            case Kind.UpdateRoleOnUser:
                await RebindAsync(SubjectKind.User, res.Users[s.Related!], (RebindSpec)s.Spec!, res, token).ConfigureAwait(false);
                break;

            case Kind.AddGroupMember:
                await _api.Groups.AddMemberAsync(
                    res.Groups[(string)s.Spec!],
                    new AddMemberRequest { UserId = res.Users[s.Related!] }, token)
                    .ConfigureAwait(false);
                break;

            case Kind.CreateServiceAccount:
            {
                var spec = (ManagementManifest.ServiceAccountSpec)s.Spec!;
                ServiceAccountCreatedResponse created = await _api.ServiceAccounts.CreateAsync(
                    new CreateServiceAccountRequest { Name = spec.Name, Description = spec.Description }, token)
                    .ConfigureAwait(false);
                res.ServiceAccounts[s.Key] = created.Id;
                // §27.5 rule 5: the one-time client_secret. ExecuteAsync reads this back
                // to attach it to this action's own outcome.
                res.CreatedServiceAccounts[s.Key] = created;
                break;
            }

            case Kind.UpdateServiceAccount:
            {
                var spec = (ManagementManifest.ServiceAccountSpec)s.Spec!;
                await _api.ServiceAccounts.UpdateAsync(
                    res.ServiceAccounts[s.Key], new UpdateServiceAccount { Description = spec.Description }, token)
                    .ConfigureAwait(false);
                break;
            }

            case Kind.AssignRoleToServiceAccount:
            {
                var binding = (ManagementManifest.RoleBinding)s.Spec!;
                await AssignAsync(SubjectKind.ServiceAccount, res.Roles[binding.Role], res.ServiceAccounts[s.Related!],
                    binding.Resource is { } r ? res.Resources[r] : null, binding.Inherit, tenantScope: null, token)
                    .ConfigureAwait(false);
                break;
            }

            case Kind.UpdateRoleOnServiceAccount:
                await RebindAsync(SubjectKind.ServiceAccount, res.ServiceAccounts[s.Related!], (RebindSpec)s.Spec!, res, token)
                    .ConfigureAwait(false);
                break;

            case Kind.Noop:
            default:
                // Never reached: ExecuteAsync short-circuits a no-op before here.
                break;
        }
    }

    /// <summary>
    /// CONTRACT.md &#167;27.6.1 item 2: assigns one role to one subject, whichever kind it
    /// is — the single call site every <c>AssignRoleTo*</c> step and the assign half of
    /// every rebind goes through, so the three subject kinds cannot drift on how
    /// <c>inherit</c>/<c>tenant_scope</c> are carried.
    /// </summary>
    private Task AssignAsync(
        SubjectKind kind, Guid roleId, Guid subjectId, Guid? resourceId, bool inherit,
        IReadOnlyList<Guid>? tenantScope, CancellationToken token)
    {
        // §27.6.1 item 2: inherit reaches the wire ONLY as false, so an inheritable
        // binding's body stays byte-for-byte a pre-1.51 body.
        bool? wireInherit = inherit ? null : false;
        return kind switch
        {
            SubjectKind.Group => _api.Roles.AssignToGroupAsync(roleId, new AssignRoleToGroupRequest
            {
                GroupId = subjectId, ResourceId = resourceId, Inherit = wireInherit, TenantScope = tenantScope,
            }, token),
            SubjectKind.User => _api.Roles.AssignToUserAsync(roleId, new AssignRoleToUserRequest
            {
                UserId = subjectId, ResourceId = resourceId, Inherit = wireInherit, TenantScope = tenantScope,
            }, token),
            SubjectKind.ServiceAccount => _api.Roles.AssignToServiceAccountAsync(roleId, new AssignRoleToServiceAccountRequest
            {
                ServiceAccountId = subjectId, ResourceId = resourceId, Inherit = wireInherit, TenantScope = tenantScope,
            }, token),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
    }

    private Task UnassignAsync(SubjectKind kind, Guid roleId, Guid subjectId, Guid? resourceId, CancellationToken token) =>
        kind switch
        {
            SubjectKind.Group => _api.Roles.UnassignFromGroupAsync(roleId, subjectId, resourceId?.ToString(), token),
            SubjectKind.User => _api.Roles.UnassignFromUserAsync(roleId, subjectId, resourceId?.ToString(), token),
            SubjectKind.ServiceAccount => _api.Roles.UnassignFromServiceAccountAsync(roleId, subjectId, resourceId?.ToString(), token),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };

    /// <summary>
    /// CONTRACT.md &#167;27.6.1 item 2: an UPDATE of a role binding is unassign, then
    /// assign — there is no update endpoint, and the two calls are not atomic. If the
    /// assign half fails, re-assigns the PREVIOUS binding (same resource, same
    /// <c>inherit</c>, same <c>tenant_scope</c> — carried across so an
    /// organization-level account's reach is never silently widened) and throws
    /// <see cref="BindingUpdateFailedException"/> naming whether that restore succeeded.
    /// If the UNASSIGN itself fails, nothing has changed yet, so it propagates as-is —
    /// there is nothing to restore.
    /// </summary>
    private async Task RebindAsync(SubjectKind kind, Guid subjectId, RebindSpec rebind, Resolved res, CancellationToken token)
    {
        Guid roleId = res.Roles[rebind.Wanted.Role];
        Guid? newResourceId = rebind.Wanted.Resource is { } r ? res.Resources[r] : null;

        await UnassignAsync(kind, roleId, subjectId, rebind.Current.ResourceId, token).ConfigureAwait(false);

        try
        {
            await AssignAsync(kind, roleId, subjectId, newResourceId, rebind.Wanted.Inherit, rebind.Current.TenantScope, token)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is AuthError or AuthzError or NetworkError)
        {
            bool restored;
            string? restoreError = null;
            try
            {
                await AssignAsync(kind, roleId, subjectId, rebind.Current.ResourceId, rebind.Current.Inherit, rebind.Current.TenantScope, token)
                    .ConfigureAwait(false);
                restored = true;
            }
            catch (Exception ex2) when (ex2 is AuthError or AuthzError or NetworkError)
            {
                restored = false;
                // N6.3: the restore's own error, kept as DATA (not only folded into the
                // thrown exception's message prose below).
                restoreError = ex2.Message;
            }

            throw new BindingUpdateFailedException(
                $"{ex.Message} (rebind restore {(restored ? "succeeded — the subject still holds its previous binding" : "FAILED — the subject now holds NEITHER the previous nor the new binding")})",
                restored,
                restoreError);
        }
    }
}
