using Agora.Infrastructure.Services;
using Agora.Web.Auth;
using Agora.Web.Services;
using Microsoft.AspNetCore.SignalR;

namespace Agora.Web.Hubs;

public sealed class ShareProgressHub(ShareManager manager, ShareCreationStatusStore statusStore) : Hub
{
    public async Task JoinShare(string token, CancellationToken ct = default)
    {
        if (Context.User is null || !Context.User.TryGetShareOwner(out var owner) || string.IsNullOrWhiteSpace(token))
        {
            throw new HubException("Unauthorized.");
        }

        var share = await manager.FindByTokenAsync(token, ct);
        if (share is not null)
        {
            if (!owner.Owns(share.OwnerUserId))
            {
                throw new HubException("Not found.");
            }
        }
        else
        {
            var status = statusStore.Read(token);
            if (status is null || status.OwnerUserId != owner.UserId)
            {
                throw new HubException("Not found.");
            }
        }

        var group = ShareProgressBroadcaster.GroupForToken(token);
        await Groups.AddToGroupAsync(Context.ConnectionId, group, ct);
    }
}
