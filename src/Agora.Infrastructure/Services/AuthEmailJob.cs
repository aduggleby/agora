using Agora.Application.Abstractions;
using Agora.Application.Models;
using Microsoft.Extensions.Logging;

namespace Agora.Infrastructure.Services;

public sealed class AuthEmailJob(IEmailSender emailSender, ILogger<AuthEmailJob> logger)
{
    public async Task SendAsync(AuthEmailMessage message, CancellationToken cancellationToken)
    {
        try
        {
            await emailSender.SendAuthEmailAsync(message, cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Auth email send failed for recipient {Recipient}", message.To);
            throw;
        }
    }
}
