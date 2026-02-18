using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class ArchiveNameResolverTests
{
    [Fact]
    public void UsesPreferredNameWhenProvided()
    {
        var result = ArchiveNameResolver.Resolve("my-share", ["a.txt"], DateTime.UnixEpoch);
        Assert.Equal("my-share.zip", result);
    }

    [Fact]
    public void UsesSingleFileBasenameWhenNoPreferredName()
    {
        var result = ArchiveNameResolver.Resolve(null, ["report.pdf"], DateTime.UnixEpoch);
        Assert.Equal("report.zip", result);
    }

    [Fact]
    public void UsesTimestampFallbackForMultipleFiles()
    {
        var now = new DateTime(2026, 2, 17, 10, 11, 12, DateTimeKind.Utc);
        var result = ArchiveNameResolver.Resolve(null, ["a.txt", "b.txt"], now);
        Assert.Equal("files-20260217-101112.zip", result);
    }
}
