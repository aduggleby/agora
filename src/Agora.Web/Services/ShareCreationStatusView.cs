using Agora.Application.Models;
using Agora.Infrastructure.Services;

namespace Agora.Web.Services;

/// <summary>
/// What an owner may see of a share that is being created or already exists: the created share wins, otherwise the
/// creation status entry (only its owner's).
/// </summary>
public sealed record ShareCreationStatusView(
    string State,
    bool Ready,
    string? Error,
    IReadOnlyList<ShareCreationStatusStore.Step> Steps,
    bool Created)
{
    public static bool IsCompleted(string state) => string.Equals(state, "completed", StringComparison.OrdinalIgnoreCase);

    /// <summary>Null when there is no such share or creation that the owner may see.</summary>
    public static async Task<ShareCreationStatusView?> ReadAsync(
        ShareManager manager, ShareCreationStatusStore statusStore, ShareOwner owner, string token, CancellationToken ct)
    {
        var share = await manager.FindByTokenAsync(token, ct);
        if (share is not null)
        {
            return owner.Owns(share.OwnerUserId)
                ? new ShareCreationStatusView("completed", true, null, [], Created: true)
                : null;
        }

        var status = statusStore.Read(token);
        if (status is null || status.OwnerUserId != owner.UserId)
        {
            return null;
        }

        return new ShareCreationStatusView(status.State, IsCompleted(status.State), status.Error, status.Steps, Created: false);
    }

    /// <summary>The browser's status JSON: a created share has no error and no steps.</summary>
    public object ToBrowserJson() => Created
        ? new { state = State, ready = Ready, steps = Array.Empty<object>() }
        : new
        {
            state = State,
            ready = Ready,
            error = Error,
            steps = Steps.Select(step => new
            {
                key = step.Key,
                label = step.Label,
                state = step.State,
                detail = step.Detail,
                updatedAtUtc = step.UpdatedAtUtc
            }).ToArray()
        };
}
