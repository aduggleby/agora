using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class PublicBaseUrlTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Normalize_EmptyIsNull(string? value)
    {
        Assert.Null(PublicBaseUrl.Normalize(value));
    }

    [Theory]
    [InlineData("https://files.example.com", "https://files.example.com")]
    [InlineData("https://files.example.com/", "https://files.example.com")]
    [InlineData(" http://localhost:18080/ ", "http://localhost:18080")]
    [InlineData("https://files.example.com:8443", "https://files.example.com:8443")]
    [InlineData("HTTPS://Files.Example.com", "https://files.example.com")]
    public void Normalize_ReturnsTheOriginWithoutTrailingSlash(string value, string expected)
    {
        Assert.Equal(expected, PublicBaseUrl.Normalize(value));
    }

    [Theory]
    [InlineData("files.example.com")]
    [InlineData("ftp://files.example.com")]
    [InlineData("https://files.example.com/agora")]
    [InlineData("https://files.example.com/?x=1")]
    [InlineData("https://files.example.com/#top")]
    [InlineData("https://user:secret@files.example.com")]
    [InlineData("/agora")]
    public void Normalize_RejectsAnythingButAnHttpOrigin(string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => PublicBaseUrl.Normalize(value));

        Assert.Contains("Agora__PublicBaseUrl", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Resolve_RequiredFailsWhenEmpty()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => PublicBaseUrl.Resolve("", required: true));

        Assert.Contains("Agora__PublicBaseUrl", ex.Message, StringComparison.Ordinal);
        Assert.Contains("not configured", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Resolve_OptionalAllowsEmpty()
    {
        Assert.Null(PublicBaseUrl.Resolve(null, required: false));
        Assert.Equal("https://files.example.com", PublicBaseUrl.Resolve("https://files.example.com/", required: false));
    }
}
