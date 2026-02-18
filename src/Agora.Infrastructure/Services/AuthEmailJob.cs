using Agora.Application.Abstractions;
using Agora.Application.Models;
using Hangfire.Console;
using Hangfire.Server;
using Microsoft.Extensions.Logging;

namespace Agora.Infrastructure.Services;

public sealed class AuthEmailJob(IEmailSender emailSender, ILogger<AuthEmailJob> logger)
{
    public async Task SendAsync(AuthEmailMessage message, CancellationToken cancellationToken, PerformContext? performContext = null)
    {
        performContext?.WriteLine($"Sending auth email to '{message.To}'.");
        try
        {
            await emailSender.SendAuthEmailAsync(message, cancellationToken);
            performContext?.WriteLine("Auth email sent.");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Auth email send failed for recipient {Recipient}", message.To);
            performContext?.WriteLine($"Auth email failed: {ex.Message}");
            throw;
        }
    }
}
