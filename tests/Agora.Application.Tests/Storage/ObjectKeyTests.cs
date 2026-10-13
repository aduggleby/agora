using Agora.Application.Utilities;

namespace Agora.Application.Tests.Storage;

public sealed class ObjectKeyTests
{
    [Theory]
    [InlineData("shares/2026/10/abc/file.txt", "shares/2026/10/abc/file.txt")]
    [InlineData("zips\\2026\\10\\x.zip", "zips/2026/10/x.zip")]
    public void Normalize_accepts_relative_keys(string key, string expected) => Assert.Equal(expected, ObjectKey.Normalize(key));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("/etc/passwd")]
    [InlineData("\\etc\\passwd")]
    [InlineData("C:\\Windows")]
    [InlineData("../../etc/passwd")]
    [InlineData("shares/./x")]
    [InlineData("shares//x")]
    [InlineData("shares/x\n")]
    public void Normalize_rejects_unsafe_keys(string? key) => Assert.Throws<ArgumentException>(() => ObjectKey.Normalize(key));

    [Theory]
    [InlineData("previews/abc/", "previews/abc/")]
    [InlineData("shares\\2026\\10\\abc\\", "shares/2026/10/abc/")]
    public void NormalizePrefix_requires_two_segments_and_trailing_slash(string prefix, string expected) =>
        Assert.Equal(expected, ObjectKey.NormalizePrefix(prefix));

    [Theory]
    [InlineData("shares/")]
    [InlineData("./")]
    [InlineData("shares/./")]
    [InlineData("previews/abc")]
    public void NormalizePrefix_rejects_root_aliases(string prefix) => Assert.Throws<ArgumentException>(() => ObjectKey.NormalizePrefix(prefix));

    [Theory]
    [InlineData("internal:uploads/templates/general/a.jpg", "uploads/templates/general/a.jpg")]
    [InlineData("internal:/zips/2026/10/a-background.png", "zips/2026/10/a-background.png")]
    [InlineData("internal:../../etc/passwd", null)]
    [InlineData("https://example.com/a.jpg", null)]
    [InlineData(null, null)]
    public void FromInternalMarker_resolves_safe_keys_only(string? marker, string? expected) =>
        Assert.Equal(expected, ObjectKey.FromInternalMarker(marker));
}
