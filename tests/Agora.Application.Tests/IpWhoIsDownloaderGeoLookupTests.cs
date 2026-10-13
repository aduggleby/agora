using System.Net;
using System.Text;
using Agora.Infrastructure.Services;
using Agora.Application.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Agora.Application.Tests;

public sealed class IpWhoIsDownloaderGeoLookupTests
{
    [Fact]
    public async Task FormatForNotificationAsync_ReturnsCityAndCountryWhenLookupSucceeds()
    {
        var responseBody = """{"success":true,"city":"Berlin","country":"Germany"}""";
        var client = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(responseBody, Encoding.UTF8, "application/json")
        }))
        {
            BaseAddress = new Uri("https://ipwho.is/")
        };
        var lookup = new IpWhoIsDownloaderGeoLookup(client, Enabled(true), NullLogger<IpWhoIsDownloaderGeoLookup>.Instance);

        var result = await lookup.FormatForNotificationAsync("8.8.8.8", CancellationToken.None);

        Assert.Equal("8.8.8.8 (Berlin, Germany)", result);
    }

    [Fact]
    public async Task FormatForNotificationAsync_FallsBackToIpOnLookupFailure()
    {
        var client = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.BadGateway)))
        {
            BaseAddress = new Uri("https://ipwho.is/")
        };
        var lookup = new IpWhoIsDownloaderGeoLookup(client, Enabled(true), NullLogger<IpWhoIsDownloaderGeoLookup>.Instance);

        var result = await lookup.FormatForNotificationAsync("1.1.1.1", CancellationToken.None);

        Assert.Equal("1.1.1.1", result);
    }

    [Fact]
    public async Task FormatForNotificationAsync_SkipsLookupForPrivateIp()
    {
        var lookup = new IpWhoIsDownloaderGeoLookup(
            new HttpClient(new StubHandler(_ => throw new InvalidOperationException("Should not be called"))),
            Enabled(true),
            NullLogger<IpWhoIsDownloaderGeoLookup>.Instance);

        var result = await lookup.FormatForNotificationAsync("10.0.0.4", CancellationToken.None);

        Assert.Equal("10.0.0.4", result);
    }

    [Fact]
    public async Task FormatForNotificationAsync_MakesNoRequestWhenDisabled()
    {
        var lookup = new IpWhoIsDownloaderGeoLookup(
            new HttpClient(new StubHandler(_ => throw new InvalidOperationException("Geo lookup must not call out when disabled"))),
            Enabled(false),
            NullLogger<IpWhoIsDownloaderGeoLookup>.Instance);

        Assert.Equal("8.8.8.8", await lookup.FormatForNotificationAsync("8.8.8.8", CancellationToken.None));
        Assert.Equal("8.8.8.8", await lookup.FormatForNotificationAsync("::ffff:8.8.8.8", CancellationToken.None));
        Assert.Equal("unknown", await lookup.FormatForNotificationAsync("", CancellationToken.None));
    }

    private static IOptions<AgoraOptions> Enabled(bool enabled) =>
        Options.Create(new AgoraOptions { GeoLookup = new AgoraGeoLookupOptions { Enabled = enabled } });

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(handler(request));
        }
    }
}
