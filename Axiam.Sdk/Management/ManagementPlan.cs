namespace Axiam.Sdk.Management;

/// <summary>What a planned step would do to the thing it names.</summary>
public enum PlanChange
{
    /// <summary>The entity does not exist and would be created.</summary>
    Create,

    /// <summary>The entity exists but differs, and would be updated in place.</summary>
    Update,

    /// <summary>The entity already matches. Reported, so a converged plan is still legible.</summary>
    NoChange,
}

/// <summary>What kind of thing a planned step is about.</summary>
public enum PlanTarget
{
    /// <summary>A resource in the hierarchy.</summary>
    Resource,

    /// <summary>A scope beneath a resource.</summary>
    Scope,

    /// <summary>A permission.</summary>
    Permission,

    /// <summary>A role.</summary>
    Role,

    /// <summary>A permission granted to a role.</summary>
    RoleGrant,

    /// <summary>A group.</summary>
    Group,

    /// <summary>A role held by a group.</summary>
    GroupRole,

    /// <summary>A user.</summary>
    User,

    /// <summary>A role held directly by a user.</summary>
    UserRole,

    /// <summary>A user's membership of a group.</summary>
    GroupMember,
}

/// <summary>One step of a plan.</summary>
/// <param name="Change">What would happen.</param>
/// <param name="Target">What kind of thing it is about.</param>
/// <param name="Key">The manifest-local key of the entry it came from.</param>
/// <param name="Summary">A one-line description, for printing a plan to a human.</param>
public sealed record PlannedAction(PlanChange Change, PlanTarget Target, string Key, string Summary);

/// <summary>
/// What reconciling a <see cref="ManagementManifest"/> would do (CONTRACT.md &#167;27.6).
/// </summary>
/// <remarks>
/// Produced by <c>Manifest.PlanAsync(...)</c>, which issues <b>reads and nothing else</b>
/// — so it is safe to run against production to find out what an apply would do.
/// </remarks>
public sealed class ManagementPlan
{
    /// <summary>Constructs a plan.</summary>
    /// <param name="actions">Every step, including the ones that would change nothing.</param>
    public ManagementPlan(IReadOnlyList<PlannedAction> actions)
    {
        Actions = actions;
    }

    /// <summary>Every step, including the ones that would change nothing.</summary>
    public IReadOnlyList<PlannedAction> Actions { get; }

    /// <summary>The subset of <see cref="Actions"/> that would actually write.</summary>
    public IReadOnlyList<PlannedAction> Changes =>
        Actions.Where(a => a.Change != PlanChange.NoChange).ToList();

    /// <summary><c>true</c> when the tenant already matches the manifest.</summary>
    public bool IsConverged => Changes.Count == 0;
}

/// <summary>What became of one applied step.</summary>
public enum ApplyStatus
{
    /// <summary>The entity did not exist and was created.</summary>
    Created,

    /// <summary>The entity existed, differed, and was updated in place.</summary>
    Updated,

    /// <summary>The entity already matched; nothing was sent.</summary>
    Unchanged,

    /// <summary>The step was attempted and the server refused it.</summary>
    Failed,

    /// <summary>An earlier step failed, so this one was never sent (&#167;27.6 rule 7).</summary>
    NotAttempted,
}

/// <summary>What became of one step, and why.</summary>
/// <param name="Status">What happened.</param>
/// <param name="Message">The server's explanation, present only on <see cref="ApplyStatus.Failed"/>.</param>
public sealed record StepOutcome(ApplyStatus Status, string? Message = null);

/// <summary>One planned step, paired with what became of it.</summary>
/// <param name="Action">The step as it was planned.</param>
/// <param name="Outcome">What happened when it ran.</param>
public sealed record AppliedStep(PlannedAction Action, StepOutcome Outcome);

/// <summary>
/// What reconciling a <see cref="ManagementManifest"/> actually did
/// (CONTRACT.md &#167;27.6).
/// </summary>
/// <remarks>
/// &#167;27.6 rule 7: apply stops at the <b>first</b> failure and does <b>not</b> roll
/// back. Everything before the failure stands; everything after it is reported as
/// <see cref="ApplyStatus.NotAttempted"/>. That is deliberate — an automatic rollback
/// would be a second unreviewed batch of writes issued at exactly the moment the tenant
/// is in a state nobody has looked at.
/// </remarks>
public sealed class ApplyReport
{
    /// <summary>Constructs a report.</summary>
    /// <param name="steps">Every step, in the order it was attempted.</param>
    public ApplyReport(IReadOnlyList<AppliedStep> steps)
    {
        Steps = steps;
    }

    /// <summary>Every step, in the order it was attempted.</summary>
    public IReadOnlyList<AppliedStep> Steps { get; }

    /// <summary>The failing step, if there was one.</summary>
    public AppliedStep? Failure => Steps.FirstOrDefault(s => s.Outcome.Status == ApplyStatus.Failed);

    /// <summary><c>true</c> when every step ran without failing.</summary>
    public bool IsComplete => Failure is null;

    /// <summary>How many steps actually wrote something.</summary>
    public int ChangedCount => Steps.Count(s =>
        s.Outcome.Status is ApplyStatus.Created or ApplyStatus.Updated);
}
