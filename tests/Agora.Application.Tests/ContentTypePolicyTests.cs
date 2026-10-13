using Agora.Application.Utilities;

namespace Agora.Application.Tests;

/// <summary>
/// Covers the single serving policy for user-uploaded content: the extension decides the type,
/// only an allowlist is served inline, and everything else becomes an octet-stream attachment.
/// </summary>
public sealed class ContentTypePolicyTests
{
    [Theory]
    [InlineData("photo.png", "image/png")]
    [InlineData("PHOTO.PNG", "image/png")]
    [InlineData("scan.jpeg", "image/jpeg")]
    [InlineData("clip.mp4", "video/mp4")]
    [InlineData("song.mp3", "audio/mpeg")]
    [InlineData("report.pdf", "application/pdf")]
    [InlineData("notes.txt", "text/plain")]
    public void Resolve_AllowlistedTypes_AreInlineWithTheirType(string fileName, string expectedType)
    {
        var plan = ContentTypePolicy.Resolve(fileName);

        Assert.Equal(expectedType, plan.ContentType);
        Assert.True(plan.Inline);
    }

    [Theory]
    [InlineData("page.html")]
    [InlineData("page.htm")]
    [InlineData("logo.svg")]
    [InlineData("doc.xhtml")]
    [InlineData("data.xml")]
    [InlineData("app.js")]
    [InlineData("style.css")]
    [InlineData("unknown.xyz")]
    [InlineData("noextension")]
    [InlineData("")]
    [InlineData(null)]
    public void Resolve_EverythingElse_IsOctetStreamAttachment(string? fileName)
    {
        var plan = ContentTypePolicy.Resolve(fileName);

        Assert.Equal("application/octet-stream", plan.ContentType);
        Assert.False(plan.Inline);
    }

    [Fact]
    public void FromFileName_IgnoresAnyDeclaredType_ExtensionWins()
    {
        // A client declaring text/html for a .png upload is irrelevant: the policy only sees the name.
        Assert.Equal("image/png", ContentTypePolicy.FromFileName("invoice.png"));
        Assert.Equal("image/png", ContentTypePolicy.Resolve("invoice.png").ContentType);
        Assert.Equal("text/html", ContentTypePolicy.FromFileName("invoice.html"));
        Assert.Equal("application/octet-stream", ContentTypePolicy.FromFileName("invoice"));
    }

    [Theory]
    [InlineData("a.png", true)]
    [InlineData("a.JPG", true)]
    [InlineData("a.gif", true)]
    [InlineData("a.webp", true)]
    [InlineData("a.bmp", true)]
    [InlineData("a.avif", true)]
    [InlineData("a.svg", false)]
    [InlineData("a.pdf", false)]
    [InlineData("a.html", false)]
    public void IsRasterImage_ExcludesSvgAndNonImages(string fileName, bool expected)
    {
        Assert.Equal(expected, ContentTypePolicy.IsRasterImage(fileName));
    }

    [Theory]
    [InlineData("bg.jpg", true)]
    [InlineData("bg.jpeg", true)]
    [InlineData("bg.png", true)]
    [InlineData("bg.webp", true)]
    [InlineData("bg.svg", false)]
    [InlineData("bg.gif", false)]
    [InlineData("bg.html", false)]
    public void IsAllowedBackgroundImage_RejectsSvg(string fileName, bool expected)
    {
        Assert.Equal(expected, ContentTypePolicy.IsAllowedBackgroundImage(fileName));
    }
}
