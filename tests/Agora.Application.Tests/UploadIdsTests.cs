using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class UploadIdsTests
{
    [Fact]
    public void AcceptsNAndDFormatsAndNormalisesToLowercaseN()
    {
        var guid = Guid.NewGuid();

        Assert.True(UploadIds.TryNormalize(guid.ToString("N").ToUpperInvariant(), out var fromN));
        Assert.True(UploadIds.TryNormalize(" " + guid.ToString("D") + " ", out var fromD));

        Assert.Equal(guid.ToString("N"), fromN);
        Assert.Equal(guid.ToString("N"), fromD);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("..")]
    [InlineData("../staged-template-backgrounds/0123456789abcdef0123456789abcdef")]
    [InlineData("..\\0123456789abcdef0123456789abcdef")]
    [InlineData("/etc/passwd")]
    [InlineData("0123456789abcdef0123456789abcdef/..")]
    [InlineData("{0123456789abcdef0123456789abcdef}")]
    [InlineData("(01234567-89ab-cdef-0123-456789abcdef)")]
    [InlineData("0123456789abcdef0123456789abcde")]
    [InlineData("0123456789abcdef0123456789abcdefa")]
    public void RejectsTraversalAndNonGuidInputs(string? rawId)
    {
        Assert.False(UploadIds.TryNormalize(rawId, out var normalized));
        Assert.Equal(string.Empty, normalized);
    }
}
