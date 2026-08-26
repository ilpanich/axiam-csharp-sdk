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
        CreateGroup, UpdateGroup, AssignRoleToGroup,
        CreateUser, UpdateUser, AssignRoleToUser, AddGroupMember,
    }

    private sealed record Step(PlannedAction Action, Kind Kind, string Key, object? Spec, string? Related);

    private sealed class Snapshot
    {
        internal IReadOnlyList<Resource> Resources { get; set; } = Array.Empty<Resource>();
        internal IReadOnlyList<Permission> Permissions { get; set; } = Array.Empty<Permission>();
        internal IReadOnlyList<Role> Roles { get; set; } = Array.Empty<Role>();
        internal IReadOnlyList<Group> Groups { get; set; } = Array.Empty<Group>();
        internal IReadOnlyList<UserResponse> Users { get; set; } = Array.Empty<UserResponse>();
        internal Dictionary<Guid, IReadOnlyList<Scope>> Scopes { get; } = new();
        internal Dictionary<Guid, IReadOnlyList<Guid>> RoleGrants { get; } = new();
        internal Dictionary<Guid, IReadOnlyList<Guid>> RoleUsers { get; } = new();
        internal Dictionary<Guid, IReadOnlyList<Guid>> RoleGroups { get; } = new();
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
            snapshot.RoleUsers[role.Id] = (await _api.Roles.ListUsersAsync(role.Id, token)
                .ConfigureAwait(false)).Select(a => a.User.Id).ToList();
            snapshot.RoleGroups[role.Id] = (await _api.Roles.ListGroupsAsync(role.Id, token)
                .ConfigureAwait(false)).Select(a => a.Group.Id).ToList();
        }

        var wantedGroups = manifest.Groups.Select(g => g.Name).ToHashSet(StringComparer.Ordinal);
        foreach (Group group in snapshot.Groups.Where(g => wantedGroups.Contains(g.Name)))
        {
            snapshot.GroupMembers[group.Id] = (await _api.Groups
                .ListMembersAllAsync(group.Id, start: PlanPage, cancellationToken: token)
                .ConfigureAwait(false)).Select(u => u.Id).ToList();
        }

        return snapshot;
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
                bool drifted = existing.ResourceType != spec.ResourceType;
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
            foreach (string roleKey in group.Roles ?? Array.Empty<string>())
            {
                string summary = $"role '{roleKey}' on group '{group.Name}'";
                bool already = res.Roles.TryGetValue(roleKey, out Guid roleId) &&
                               res.Groups.TryGetValue(group.Key, out Guid groupId) &&
                               snap.RoleGroups.TryGetValue(roleId, out IReadOnlyList<Guid>? held) &&
                               held.Contains(groupId);
                outSteps.Add(MakeStep(
                    already ? PlanChange.NoChange : PlanChange.Create, PlanTarget.GroupRole,
                    group.Key, summary, already ? Kind.Noop : Kind.AssignRoleToGroup,
                    roleKey, group.Key));
            }
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
            foreach (string roleKey in user.Roles ?? Array.Empty<string>())
            {
                string summary = $"role '{roleKey}' on user '{user.Username}'";
                bool already = res.Roles.TryGetValue(roleKey, out Guid roleId) &&
                               res.Users.TryGetValue(user.Key, out Guid userId) &&
                               snap.RoleUsers.TryGetValue(roleId, out IReadOnlyList<Guid>? held) &&
                               held.Contains(userId);
                outSteps.Add(MakeStep(
                    already ? PlanChange.NoChange : PlanChange.Create, PlanTarget.UserRole,
                    user.Key, summary, already ? Kind.Noop : Kind.AssignRoleToUser,
                    roleKey, user.Key));
            }
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

        return outSteps;
    }

    private static Step MakeStep(
        PlanChange change, PlanTarget target, string key, string summary,
        Kind kind, object? spec, string? related)
        => new(new PlannedAction(change, target, key, summary), kind, key, spec, related);

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
                applied.Add(new AppliedStep(
                    step.Action, new StepOutcome(ApplyStatus.Failed, ex.Message)));
                stopped = true;
                continue;
            }

            ApplyStatus status = step.Kind.ToString().StartsWith("Update", StringComparison.Ordinal)
                ? ApplyStatus.Updated
                : ApplyStatus.Created;
            applied.Add(new AppliedStep(step.Action, new StepOutcome(status)));
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
                    }, token).ConfigureAwait(false);
                res.Resources[s.Key] = created.Id;
                break;
            }

            case Kind.UpdateResource:
            {
                var spec = (ManagementManifest.ResourceSpec)s.Spec!;
                await _api.Resources.UpdateAsync(
                    res.Resources[s.Key],
                    new UpdateResourceRequest { ResourceType = spec.ResourceType }, token)
                    .ConfigureAwait(false);
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
                await _api.Roles.AssignToGroupAsync(
                    res.Roles[(string)s.Spec!],
                    new AssignRoleToGroupRequest { GroupId = res.Groups[s.Related!] }, token)
                    .ConfigureAwait(false);
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
                await _api.Roles.AssignToUserAsync(
                    res.Roles[(string)s.Spec!],
                    new AssignRoleToUserRequest { UserId = res.Users[s.Related!] }, token)
                    .ConfigureAwait(false);
                break;

            case Kind.AddGroupMember:
                await _api.Groups.AddMemberAsync(
                    res.Groups[(string)s.Spec!],
                    new AddMemberRequest { UserId = res.Users[s.Related!] }, token)
                    .ConfigureAwait(false);
                break;

            case Kind.Noop:
            default:
                // Never reached: ExecuteAsync short-circuits a no-op before here.
                break;
        }
    }
}
