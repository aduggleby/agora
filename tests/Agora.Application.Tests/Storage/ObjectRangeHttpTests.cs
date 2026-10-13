using System.Net;
using System.Net.Http.Headers;
using Agora.Application.Abstractions;
using Agora.Web.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;

namespace Agora.Application.Tests.Storage;

/// <summary>
/// HTTP-level range behaviour of <see cref="ObjectResults.File"/> (the helper the download endpoints use) over each
/// store's stream: bounded/suffix/open-ended ranges, 416, If-Range and empty objects.
/// </summary>
public abstract class ObjectRangeHttpTests
{
    private static readonly byte[] Content = Enumerable.Range(0, 1000).Select(i => (byte)(i % 251)).ToArray();

    protected abstract ObjectStoreScope CreateScope();

    [SkippableFact]
    public async Task Serves_full_and_ranged_responses()
    {
        await using var scope = CreateScope();
        await using var app = await StartAsync(scope.Store);
        var client = app.GetTestClient();
        var key = scope.Key("http/data.bin");
        await scope.Store.PutBytesAsync(key, Content, null, CancellationToken.None);

        var full = await client.GetAsync($"/o/{key}");
        Assert.Equal(HttpStatusCode.OK, full.StatusCode);
        Assert.Equal("bytes", full.Headers.AcceptRanges.Single());
        Assert.NotNull(full.Headers.ETag);
        Assert.NotNull(full.Content.Headers.LastModified);
        Assert.Equal(Content, await full.Content.ReadAsByteArrayAsync());

        await AssertRangeAsync(client, key, "bytes=100-199", 100, 199);
        await AssertRangeAsync(client, key, "bytes=-100", 900, 999);
        await AssertRangeAsync(client, key, "bytes=950-", 950, 999);
        await AssertRangeAsync(client, key, "bytes=990-5000", 990, 999);

        var unsatisfiable = await SendAsync(client, key, request => request.Headers.Range = RangeHeaderValue.Parse("bytes=2000-3000"));
        Assert.Equal(HttpStatusCode.RequestedRangeNotSatisfiable, unsatisfiable.StatusCode);
        Assert.Equal("bytes */1000", unsatisfiable.Content.Headers.GetValues("Content-Range").Single());
    }

    [SkippableFact]
    public async Task If_range_serves_range_only_for_the_current_validator()
    {
        await using var scope = CreateScope();
        await using var app = await StartAsync(scope.Store);
        var client = app.GetTestClient();
        var key = scope.Key("http/if-range.bin");
        await scope.Store.PutBytesAsync(key, Content, null, CancellationToken.None);
        var etag = (await client.GetAsync($"/o/{key}")).Headers.ETag!;

        var match = await SendAsync(client, key, request =>
        {
            request.Headers.Range = RangeHeaderValue.Parse("bytes=10-19");
            request.Headers.IfRange = new RangeConditionHeaderValue(etag);
        });
        Assert.Equal(HttpStatusCode.PartialContent, match.StatusCode);
        Assert.Equal(Content[10..20], await match.Content.ReadAsByteArrayAsync());

        var mismatch = await SendAsync(client, key, request =>
        {
            request.Headers.Range = RangeHeaderValue.Parse("bytes=10-19");
            request.Headers.IfRange = new RangeConditionHeaderValue(new EntityTagHeaderValue("\"stale\""));
        });
        Assert.Equal(HttpStatusCode.OK, mismatch.StatusCode);
        Assert.Equal(Content, await mismatch.Content.ReadAsByteArrayAsync());
    }

    [SkippableFact]
    public async Task Empty_object_is_served_without_ranges()
    {
        await using var scope = CreateScope();
        await using var app = await StartAsync(scope.Store);
        var client = app.GetTestClient();
        var key = scope.Key("http/empty.bin");
        await scope.Store.PutBytesAsync(key, [], null, CancellationToken.None);

        var full = await client.GetAsync($"/o/{key}");
        Assert.Equal(HttpStatusCode.OK, full.StatusCode);
        Assert.Empty(await full.Content.ReadAsByteArrayAsync());

        var ranged = await SendAsync(client, key, request => request.Headers.Range = RangeHeaderValue.Parse("bytes=0-10"));
        Assert.Equal(HttpStatusCode.RequestedRangeNotSatisfiable, ranged.StatusCode);
        Assert.Empty(await ranged.Content.ReadAsByteArrayAsync());

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/o/{scope.Key("http/missing.bin")}")).StatusCode);
    }

    private static async Task AssertRangeAsync(HttpClient client, string key, string range, long from, long to)
    {
        var response = await SendAsync(client, key, request => request.Headers.Range = RangeHeaderValue.Parse(range));
        Assert.Equal(HttpStatusCode.PartialContent, response.StatusCode);
        Assert.Equal($"bytes {from}-{to}/1000", response.Content.Headers.ContentRange!.ToString());
        Assert.Equal(Content[(int)from..(int)(to + 1)], await response.Content.ReadAsByteArrayAsync());
    }

    private static Task<HttpResponseMessage> SendAsync(HttpClient client, string key, Action<HttpRequestMessage> configure)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, $"/o/{key}");
        configure(request);
        return client.SendAsync(request);
    }

    private static async Task<WebApplication> StartAsync(IObjectStore store)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        app.MapGet("/o/{**key}", async (string key, CancellationToken ct) =>
            await store.OpenReadAsync(key, ct) is { } obj
                ? ObjectResults.File(obj, "application/octet-stream")
                : Results.NotFound());
        await app.StartAsync();
        return app;
    }
}

public sealed class FileSystemObjectRangeHttpTests : ObjectRangeHttpTests
{
    protected override ObjectStoreScope CreateScope() => ObjectStoreScope.FileSystem();
}

public sealed class MinioObjectRangeHttpTests(MinioFixture fixture) : ObjectRangeHttpTests, IClassFixture<MinioFixture>
{
    protected override ObjectStoreScope CreateScope()
    {
        S3TestEnvironment.SkipOrFail(fixture.UnavailableReason);
        return ObjectStoreScope.S3(fixture.Client, MinioFixture.Bucket, "http");
    }
}
