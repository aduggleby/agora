using Agora.Infrastructure.Services;
using Agora.Web.Services;
using Microsoft.AspNetCore.SignalR;

namespace Agora.Web.Hubs;

public sealed class ShareProgressHub(ShareManager manager, ShareCreationStatusStore statusStore) : Hub
{
    public async Task JoinShare(string token, CancellationToken ct = default)
    {
        var email = Context.User?.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value ?? string.Empty;
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
        {
            throw new HubException("Unauthorized.");
        }

        var share = await manager.FindByTokenAsync(token, ct);
        if (share is not null)
        {
            if (!string.Equals(share.UploaderEmail, email, StringComparison.OrdinalIgnoreCase))
            {
                throw new HubException("Not found.");
            }
        }
        else
        {
            var status = statusStore.Read(token);
            if (status is null || !string.Equals(status.UploaderEmail, email, StringComparison.OrdinalIgnoreCase))
            {
                throw new HubException("Not found.");
            }
        }

        var group = ShareProgressBroadcaster.GroupForToken(token);
        await Groups.AddToGroupAsync(Context.ConnectionId, group, ct);
    }
}
