using Agora.Infrastructure.Services;

namespace Agora.Web.Background;

public sealed class ExpiredShareCleanupService(IServiceScopeFactory scopeFactory, ILogger<ExpiredShareCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var manager = scope.ServiceProvider.GetRequiredService<ShareManager>();
                var cleaned = await manager.CleanupExpiredSharesAsync(stoppingToken);
                if (cleaned > 0)
                {
                    logger.LogInformation("Cleanup removed {Count} expired shares", cleaned);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Expired share cleanup failed");
            }

            await Task.Delay(TimeSpan.FromMinutes(30), stoppingToken);
        }
    }
}
