using Agora.Application.Models;

namespace Agora.Application.Abstractions;

public interface IEmailSender
{
    Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken);
}
