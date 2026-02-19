namespace Agora.Infrastructure.Services;

public interface IDownloaderGeoLookup
{
    Task<string> FormatForNotificationAsync(string ipAddress, CancellationToken cancellationToken);
}
