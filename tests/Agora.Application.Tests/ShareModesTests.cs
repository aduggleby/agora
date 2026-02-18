using Agora.Application.Models;

namespace Agora.Application.Tests;

public sealed class ShareModesTests
{
    [Theory]
    [InlineData("archive", ShareExperienceType.Archive)]
    [InlineData("site", ShareExperienceType.Site)]
    [InlineData("gallery", ShareExperienceType.Gallery)]
    [InlineData("unknown", ShareExperienceType.Archive)]
    public void ParseExperienceType_MapsExpectedValues(string input, ShareExperienceType expected)
    {
        Assert.Equal(expected, ShareModes.ParseExperienceType(input));
    }

    [Theory]
    [InlineData("download_only", ShareAccessMode.DownloadOnly)]
    [InlineData("preview_only", ShareAccessMode.PreviewOnly)]
    [InlineData("preview_and_download", ShareAccessMode.PreviewAndDownload)]
    [InlineData("unknown", ShareAccessMode.DownloadOnly)]
    public void ParseAccessMode_MapsExpectedValues(string input, ShareAccessMode expected)
    {
        Assert.Equal(expected, ShareModes.ParseAccessMode(input));
    }

    [Fact]
    public void AccessModePolicies_AreConsistent()
    {
        Assert.True(ShareModes.AllowsZipDownload(ShareAccessMode.DownloadOnly));
        Assert.False(ShareModes.AllowsPreview(ShareAccessMode.DownloadOnly));

        Assert.False(ShareModes.AllowsZipDownload(ShareAccessMode.PreviewOnly));
        Assert.True(ShareModes.AllowsPreview(ShareAccessMode.PreviewOnly));

        Assert.True(ShareModes.AllowsZipDownload(ShareAccessMode.PreviewAndDownload));
        Assert.True(ShareModes.AllowsPreview(ShareAccessMode.PreviewAndDownload));
    }
}
