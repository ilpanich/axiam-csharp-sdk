namespace Axiam.Sdk.Management;

/// <summary>
/// Where to start a paginated read and how much to ask for
/// (CONTRACT.md &#167;27.4 rule 4).
/// </summary>
/// <remarks>
/// A <see cref="Limit"/> of <c>null</c> means "do not send one", which is not the same
/// as sending zero: the server reads <c>limit=0</c> as none and answers with an empty
/// page. Leaving it out lets the server apply its own default, and
/// <see cref="Page{T}.Total"/> still tells the caller the rest exists.
/// </remarks>
public sealed class PageRequest
{
    /// <summary>Constructs a window.</summary>
    /// <param name="offset">How many items to skip; never negative.</param>
    /// <param name="limit">How many to ask for, or <c>null</c> to let the server decide.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// If <paramref name="offset"/> is negative, or <paramref name="limit"/> is present
    /// and not positive.
    /// </exception>
    public PageRequest(int offset = 0, int? limit = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        if (limit is { } l)
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(l, 0);
        }

        Offset = offset;
        Limit = limit;
    }

    /// <summary>How many items to skip.</summary>
    public int Offset { get; }

    /// <summary>How many to ask for, or <c>null</c> for the server's own default.</summary>
    public int? Limit { get; }

    /// <summary>The first page, with the server's own default size.</summary>
    /// <returns>A window starting at zero with no limit.</returns>
    public static PageRequest First() => new();

    /// <summary>The first page of <paramref name="limit"/> items.</summary>
    /// <param name="limit">The page size to request.</param>
    /// <returns>A window starting at zero.</returns>
    public static PageRequest Of(int limit) => new(0, limit);

    /// <summary>The next window of the same size, for a manual walk.</summary>
    /// <param name="consumed">How many items the previous page returned.</param>
    /// <returns>A window advanced past what was consumed.</returns>
    public PageRequest Next(int consumed) => new(Offset + consumed, Limit);
}

/// <summary>
/// One page of a paginated read (CONTRACT.md &#167;27.4 rule 4).
/// </summary>
/// <typeparam name="T">The item type this page carries.</typeparam>
/// <remarks>
/// <see cref="Total"/> is the size of the <b>whole</b> set, not of <see cref="Items"/>.
/// That distinction is the entire reason this type exists rather than a bare list: an
/// SDK that returned the list alone would let a caller conclude a tenant has 50 users
/// because the first page held 50, and &#167;27.4 rule 4 forbids exactly that.
/// </remarks>
public sealed class Page<T>
{
    /// <summary>Constructs a page.</summary>
    /// <param name="items">This page's items, in the server's order.</param>
    /// <param name="total">How many items exist in total, as the server reported it.</param>
    /// <param name="offset">The offset this page starts at.</param>
    /// <param name="limit">The page size the server actually applied.</param>
    public Page(IReadOnlyList<T> items, int total, int offset, int limit)
    {
        Items = items;
        Total = total;
        Offset = offset;
        Limit = limit;
    }

    /// <summary>This page's items, in the server's order.</summary>
    public IReadOnlyList<T> Items { get; }

    /// <summary>How many items exist in total — NOT how many this page holds.</summary>
    public int Total { get; }

    /// <summary>The offset this page starts at.</summary>
    public int Offset { get; }

    /// <summary>The page size the server actually applied.</summary>
    public int Limit { get; }

    /// <summary><c>true</c> when this page is the last one the server can produce.</summary>
    public bool IsLast => Items.Count == 0 || Offset + Items.Count >= Total;

    /// <summary>Where the next page starts, or <c>null</c> when <see cref="IsLast"/>.</summary>
    /// <returns>The next window, or <c>null</c>.</returns>
    public PageRequest? NextPage() =>
        IsLast ? null : new PageRequest(Offset + Items.Count, Limit > 0 ? Limit : null);

    /// <summary>An empty page, for a read the server answered with no body.</summary>
    /// <returns>A page with no items and a total of zero.</returns>
    public static Page<T> Empty() => new(Array.Empty<T>(), 0, 0, 0);
}

/// <summary>
/// A per-handle override of the organization or tenant a route interpolates
/// (CONTRACT.md &#167;27.4 rule 3).
/// </summary>
/// <param name="OrgId">The organization to address, or <c>null</c> to inherit.</param>
/// <param name="TenantId">The tenant to address, or <c>null</c> to inherit.</param>
/// <remarks>
/// Both <c>null</c> means "inherit from the client", which is the ordinary case. A
/// handle carrying an override is a <b>new</b> handle: <c>InOrg(...)</c> never mutates
/// the one it was called on, so a scoped call cannot leak into unrelated code holding
/// the same reference.
/// </remarks>
public sealed record NamespaceScope(Guid? OrgId = null, Guid? TenantId = null);
