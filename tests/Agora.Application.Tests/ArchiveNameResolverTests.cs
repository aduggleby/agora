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

public sealed class ArchiveNameSanitizeTests
{
    [Theory]
    [InlineData("..\\evil.txt", "evil.txt")]
    [InlineData("..\\..\\evil.exe", "evil.exe")]
    [InlineData("../../evil.txt", "evil.txt")]
    [InlineData("/etc/passwd", "passwd")]
    [InlineData("\\\\server\\share\\doc.pdf", "doc.pdf")]
    [InlineData("C:\\Users\\x\\report.docx", "report.docx")]
    [InlineData("nested/dir/photo.jpg", "photo.jpg")]
    [InlineData("..", "archive")]
    [InlineData("...", "archive")]
    [InlineData("   ", "archive")]
    [InlineData("a\u0000b.txt", "ab.txt")]
    [InlineData("trailing. ", "trailing")]
    [InlineData("C:evil", "C_evil")]
    [InlineData("a.txt:stream", "a.txt_stream")]
    public void Sanitize_KeepsOnlyTheFinalSegment(string input, string expected)
    {
        Assert.Equal(expected, ArchiveNameResolver.Sanitize(input));
    }

    [Fact]
    public void Deduplicate_AppendsCountersBeforeTheExtension()
    {
        var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        Assert.Equal("a.txt", ArchiveNameResolver.Deduplicate("a.txt", taken));
        Assert.Equal("A (2).TXT", ArchiveNameResolver.Deduplicate("A.TXT", taken));
        Assert.Equal("a (3).txt", ArchiveNameResolver.Deduplicate("a.txt", taken));
        Assert.Equal("noext", ArchiveNameResolver.Deduplicate("noext", taken));
        Assert.Equal("noext (2)", ArchiveNameResolver.Deduplicate("noext", taken));
    }
}
