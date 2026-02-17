using Agora.Application.Models;

namespace Agora.Application.Abstractions;

public interface IEmailSender
{
    Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken);
    Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken);
}

public interface IEmailTemplateRenderer
{
    Task<string> RenderDownloadNotificationHtmlAsync(DownloadNotification notification, CancellationToken cancellationToken);
    Task<string> RenderAuthEmailHtmlAsync(AuthEmailMessage message, CancellationToken cancellationToken);
}
