using Axiam.Sdk.Core;

namespace Axiam.Sdk.Management;

/// <summary>
/// Checks a <see cref="ManagementManifest"/> before a single request goes out
/// (CONTRACT.md &#167;27.6 rule 1).
/// </summary>
/// <remarks>
/// Everything here is answerable from the manifest alone, so it is answered from the
/// manifest alone: a dangling reference or a cycle discovered halfway through an apply
/// leaves the tenant part-reconciled, and the fix is one the caller could have been told
/// about before anything was written.
/// </remarks>
internal static class ManifestValidation
{
    /// <summary>
    /// Reports every problem at once, or nothing.
    /// </summary>
    /// <remarks>
    /// Every problem rather than the first: fixing them one run at a time is the slowest
    /// possible way to learn about six of them.
    /// </remarks>
    internal static void Validate(ManagementManifest manifest)
    {
        var problems = new List<string>();
        var resourceKeys = manifest.Resources.Select(r => r.Key).ToHashSet(StringComparer.Ordinal);
        var scopeKeys = manifest.Resources
            .SelectMany(r => r.Scopes ?? Array.Empty<ManagementManifest.ScopeSpec>())
            .Select(s => s.Key).ToHashSet(StringComparer.Ordinal);
        var permissionKeys = manifest.Permissions.Select(p => p.Key).ToHashSet(StringComparer.Ordinal);
        var roleKeys = manifest.Roles.Select(r => r.Key).ToHashSet(StringComparer.Ordinal);
        var groupKeys = manifest.Groups.Select(g => g.Key).ToHashSet(StringComparer.Ordinal);

        Duplicates(manifest.Resources.Select(r => r.Key), "resource", problems);
        Duplicates(manifest.Permissions.Select(p => p.Key), "permission", problems);
        Duplicates(manifest.Roles.Select(r => r.Key), "role", problems);
        Duplicates(manifest.Groups.Select(g => g.Key), "group", problems);
        Duplicates(manifest.Users.Select(u => u.Key), "user", problems);

        foreach (ManagementManifest.ResourceSpec resource in manifest.Resources)
        {
            if (resource.Parent is { } parent && !resourceKeys.Contains(parent))
            {
                problems.Add($"resource '{resource.Key}' names parent '{parent}', " +
                             "which no resource declares");
            }
        }

        foreach (ManagementManifest.RoleSpec role in manifest.Roles)
        {
            foreach (ManagementManifest.GrantSpec grant in
                     role.Grants ?? Array.Empty<ManagementManifest.GrantSpec>())
            {
                if (!permissionKeys.Contains(grant.Permission))
                {
                    problems.Add($"role '{role.Key}' grants '{grant.Permission}', " +
                                 "which no permission declares");
                }

                foreach (string scope in grant.Scopes ?? Array.Empty<string>())
                {
                    if (!scopeKeys.Contains(scope))
                    {
                        problems.Add($"role '{role.Key}' narrows a grant to scope '{scope}', " +
                                     "which no resource declares");
                    }
                }

                if (grant.Effect is { } effect && effect != "allow" && effect != "deny")
                {
                    problems.Add($"role '{role.Key}' grants '{grant.Permission}' with effect " +
                                 $"'{effect}'; only 'allow' and 'deny' exist");
                }
            }
        }

        var rolesByKey = manifest.Roles
            .GroupBy(r => r.Key, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        Duplicates(manifest.ServiceAccounts.Select(a => a.Key), "service account", problems);

        foreach (ManagementManifest.GroupSpec group in manifest.Groups)
        {
            RoleBindings(group.Roles, resourceKeys, rolesByKey, $"group '{group.Key}'", problems);
        }

        foreach (ManagementManifest.UserSpec user in manifest.Users)
        {
            RoleBindings(user.Roles, resourceKeys, rolesByKey, $"user '{user.Key}'", problems);

            foreach (string group in user.Groups ?? Array.Empty<string>())
            {
                if (!groupKeys.Contains(group))
                {
                    problems.Add($"user '{user.Key}' joins group '{group}', which no group declares");
                }
            }
        }

        foreach (ManagementManifest.ServiceAccountSpec account in manifest.ServiceAccounts)
        {
            RoleBindings(account.Roles, resourceKeys, rolesByKey, $"service account '{account.Key}'", problems);
        }

        if (Cycle(manifest) is { } cycle)
        {
            problems.Add(cycle);
        }

        if (problems.Count > 0)
        {
            throw NetworkError.FromMessage(
                "this manifest cannot be reconciled:\n  - " + string.Join("\n  - ", problems) +
                "\n\nNothing was sent: §27.6 rule 1 refuses a manifest before the first " +
                "request rather than part-way through an apply.");
        }
    }

    /// <summary>
    /// CONTRACT.md &#167;27.6.1 item 2 (contract 1.51): checks one subject's
    /// <see cref="ManagementManifest.RoleBinding"/> list — dangling role/resource
    /// references, a role bound twice to this subject (plain-and-scoped included, the
    /// server's <c>(subject, role)</c> uniqueness expressed client-side), and a global
    /// role bound with <c>inherit: false</c> (the server refuses it with <c>400</c>; an
    /// SDK MAY pre-empt it, and this one does, since it needs no server state).
    /// </summary>
    private static void RoleBindings(
        IReadOnlyList<ManagementManifest.RoleBinding>? bindings,
        HashSet<string> resourceKeys,
        Dictionary<string, ManagementManifest.RoleSpec> rolesByKey,
        string subjectDescription,
        List<string> problems)
    {
        foreach (ManagementManifest.RoleBinding binding in bindings ?? Array.Empty<ManagementManifest.RoleBinding>())
        {
            if (!rolesByKey.ContainsKey(binding.Role))
            {
                problems.Add($"{subjectDescription} holds role '{binding.Role}', which no role declares");
                continue;
            }

            if (binding.Resource is { } resource && !resourceKeys.Contains(resource))
            {
                problems.Add($"{subjectDescription}'s binding of role '{binding.Role}' names resource " +
                             $"'{resource}', which no resource declares");
            }

            if (!binding.Inherit && rolesByKey[binding.Role].Global)
            {
                problems.Add($"{subjectDescription}'s binding of role '{binding.Role}' sets " +
                             "inherit: false on a global role, which the server refuses with 400 " +
                             "(a global role applies everywhere and ignores resource scope)");
            }
        }

        foreach (var group in (bindings ?? Array.Empty<ManagementManifest.RoleBinding>())
                 .GroupBy(b => b.Role, StringComparer.Ordinal)
                 .Where(g => g.Count() > 1))
        {
            problems.Add($"{subjectDescription} binds role '{group.Key}' more than once " +
                         "(plain and/or resource-scoped); the server keys an assignment on " +
                         "(subject, role) alone, so this describes a state it cannot hold");
        }
    }

    private static void Duplicates(IEnumerable<string> keys, string what, List<string> problems)
    {
        foreach (string key in keys.GroupBy(k => k, StringComparer.Ordinal)
                     .Where(g => g.Count() > 1).Select(g => g.Key)
                     .OrderBy(k => k, StringComparer.Ordinal))
        {
            problems.Add($"{what} key '{key}' is declared more than once; keys must be unique");
        }
    }

    /// <summary>
    /// Names a resource cycle, or <c>null</c>.
    /// </summary>
    /// <remarks>
    /// A cycle is not merely invalid, it is unreconcilable: neither resource can be
    /// created before the other, and a reconciler that did not check would loop rather
    /// than fail.
    /// </remarks>
    private static string? Cycle(ManagementManifest manifest)
    {
        Dictionary<string, string?> parents = manifest.Resources
            .GroupBy(r => r.Key, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Parent, StringComparer.Ordinal);
        foreach (string start in parents.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            var seen = new HashSet<string>(StringComparer.Ordinal) { start };
            string? at = parents[start];
            while (at is not null)
            {
                if (!seen.Add(at))
                {
                    return $"resource '{start}' is its own ancestor via '{at}'; a parent cycle " +
                           "can never be created in any order";
                }

                at = parents.TryGetValue(at, out string? next) ? next : null;
            }
        }

        return null;
    }

    /// <summary>
    /// Resource keys ordered so a parent always precedes its children.
    /// </summary>
    /// <remarks>
    /// &#167;27.6 rule 2: ordering is DERIVED, not declared. A manifest that lists a
    /// child first is not wrong, it is just a manifest — the reconciler is what knows a
    /// parent has to exist first.
    /// </remarks>
    internal static IReadOnlyList<string> TopologicalOrder(ManagementManifest manifest)
    {
        Dictionary<string, string?> parents = manifest.Resources
            .GroupBy(r => r.Key, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First().Parent, StringComparer.Ordinal);
        var ordered = new List<string>();
        var placed = new HashSet<string>(StringComparer.Ordinal);

        void Place(string key)
        {
            if (placed.Contains(key))
            {
                return;
            }

            if (parents.TryGetValue(key, out string? parent) && parent is not null &&
                parents.ContainsKey(parent))
            {
                Place(parent);
            }

            if (placed.Add(key))
            {
                ordered.Add(key);
            }
        }

        foreach (ManagementManifest.ResourceSpec resource in manifest.Resources)
        {
            Place(resource.Key);
        }

        return ordered;
    }
}
