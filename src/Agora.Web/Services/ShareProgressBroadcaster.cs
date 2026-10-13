using System.Security.Cryptography;
using System.Text;
using Agora.Web.Hubs;
using Microsoft.AspNetCore.SignalR;

namespace Agora.Web.Services;

public sealed class ShareProgressBroadcaster(IHubContext<ShareProgressHub> hubContext)
{
    public static string GroupForToken(string token)
    {
        var normalized = (token ?? string.Empty).Trim();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized))).ToLowerInvariant();
        return $"share-progress:{hash}";
    }

    public Task BroadcastAsync(ShareCreationStatusStore.Entry entry, CancellationToken ct = default)
    {
        var group = GroupForToken(entry.Token);
        return hubContext.Clients.Group(group).SendAsync("shareStatus", new
        {
            token = entry.Token,
            state = entry.State,
            error = entry.Error,
            steps = entry.Steps.Select(step => new
            {
                key = step.Key,
                label = step.Label,
                state = step.State,
                detail = step.Detail,
                updatedAtUtc = step.UpdatedAtUtc
            }).ToArray(),
            updatedAtUtc = entry.UpdatedAtUtc
        }, ct);
    }
}
