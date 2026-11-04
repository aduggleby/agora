using Agora.Application.Utilities;
using Agora.Web.Endpoints;

namespace Agora.Application.Tests;

public sealed class ApiTokensTests
{
    // RFC 7636 appendix B.
    private const string RfcVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string RfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [Fact]
    public void NewToken_has_prefix_and_43_base64url_characters_and_is_well_formed()
    {
        var token = ApiTokens.NewToken();

        Assert.StartsWith("agora_pat_", token);
        Assert.Equal(10 + 43, token.Length);
        Assert.True(ApiTokens.IsWellFormedToken(token));
        Assert.NotEqual(token, ApiTokens.NewToken());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("agora_pat_")]
    [InlineData("agora_pat_short")]
    [InlineData("AGORA_PAT_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
    [InlineData("agora_pat_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX+")]
    [InlineData("agora_pat_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk ")]
    public void IsWellFormedToken_rejects_anything_else(string? value) => Assert.False(ApiTokens.IsWellFormedToken(value));

    [Fact]
    public void DisplayPrefix_is_the_8_characters_after_the_fixed_prefix()
    {
        Assert.Equal("dBjftJeZ", ApiTokens.DisplayPrefix("agora_pat_" + RfcVerifier));
    }

    [Fact]
    public void Hash_is_lower_case_hex_sha256_and_never_the_input()
    {
        var token = ApiTokens.NewToken();
        var hash = ApiTokens.Hash(token);

        Assert.Equal(64, hash.Length);
        Assert.Equal(hash.ToLowerInvariant(), hash);
        Assert.DoesNotContain(token[10..], hash);
        Assert.Equal(hash, ApiTokens.Hash(token));
    }

    [Fact]
    public void VerifyPkce_accepts_the_rfc_example()
    {
        Assert.Equal(RfcChallenge, ApiTokens.S256Challenge(RfcVerifier));
        Assert.True(ApiTokens.VerifyPkce(RfcVerifier, RfcChallenge));
    }

    [Theory]
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl")] // one character off
    [InlineData("short")] // below 43 characters
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX!")] // not unreserved
    [InlineData("")]
    [InlineData(null)]
    public void VerifyPkce_rejects_a_wrong_or_malformed_verifier(string? verifier) =>
        Assert.False(ApiTokens.VerifyPkce(verifier, RfcChallenge));

    [Fact]
    public void VerifyPkce_rejects_the_plain_method_where_the_challenge_is_the_verifier()
    {
        // With "plain" the challenge would equal the verifier; S256 never accepts that.
        Assert.False(ApiTokens.VerifyPkce(RfcVerifier, RfcVerifier));
    }

    [Theory]
    [InlineData("S256", true)]
    [InlineData("plain", false)]
    [InlineData("s256", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Only_S256_is_a_supported_challenge_method(string? method, bool expected) =>
        Assert.Equal(expected, ApiTokens.IsSupportedChallengeMethod(method));

    [Theory]
    [InlineData("http://127.0.0.1:1024/callback")]
    [InlineData("http://127.0.0.1:49152/callback")]
    [InlineData("http://127.0.0.1:65535/callback")]
    [InlineData("http://[::1]:50000/callback")]
    public void IsValidRedirectUri_accepts_loopback_callbacks(string uri) => Assert.True(ApiTokens.IsValidRedirectUri(uri));

    [Theory]
    [InlineData("http://localhost:50000/callback")]
    [InlineData("https://127.0.0.1:50000/callback")]
    [InlineData("HTTP://127.0.0.1:50000/callback")]
    [InlineData("http://127.0.0.1:50000/other")]
    [InlineData("http://127.0.0.1:50000/callback/")]
    [InlineData("http://127.0.0.1:50000/Callback")]
    [InlineData("http://127.0.0.1:50000/callback?x=1")]
    [InlineData("http://127.0.0.1:50000/callback#x")]
    [InlineData("http://127.0.0.1/callback")]
    [InlineData("http://127.0.0.1:1023/callback")]
    [InlineData("http://127.0.0.1:65536/callback")]
    [InlineData("http://127.0.0.1:099999/callback")]
    [InlineData("http://127.0.0.1:08080/callback")]
    [InlineData("http://127.0.0.1@evil.com:80/callback")]
    [InlineData("http://user@127.0.0.1:50000/callback")]
    [InlineData("http://127.0.0.1:50000@evil.com/callback")]
    [InlineData("http://127.0.0.2:50000/callback")]
    [InlineData("http://[::2]:50000/callback")]
    [InlineData("http://evil.com:50000/callback")]
    [InlineData(" http://127.0.0.1:50000/callback")]
    [InlineData("http://127.0.0.1:50000/callback\n")]
    [InlineData("")]
    [InlineData(null)]
    public void IsValidRedirectUri_rejects_everything_else(string? uri) => Assert.False(ApiTokens.IsValidRedirectUri(uri));

    [Theory]
    [InlineData("  AgoraCapture on Alex's MacBook  ", "AgoraCapture on Alex's MacBook")]
    [InlineData("Mac\u0000Book\u001b[31m", "MacBook[31m")]
    [InlineData("evil‮koobcam", "evilkoobcam")]
    [InlineData("", "Unknown device")]
    [InlineData("   \t ", "Unknown device")]
    [InlineData(null, "Unknown device")]
    public void SanitizeDeviceName_trims_and_strips_control_and_format_characters(string? raw, string expected) =>
        Assert.Equal(expected, ApiTokens.SanitizeDeviceName(raw));

    [Theory]
    [InlineData("abc", true)]
    [InlineData("dBjftJeZ4CVP-mB92K27uh", true)]
    [InlineData("with space and ~!", true)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("tab\there", false)]
    [InlineData("caf\u00e9", false)]
    public void IsValidState_accepts_printable_ascii_only(string? state, bool expected) =>
        Assert.Equal(expected, ApiTokens.IsValidState(state));

    [Fact]
    public void IsValidState_caps_length()
    {
        Assert.True(ApiTokens.IsValidState(new string('a', ApiTokens.MaxStateLength)));
        Assert.False(ApiTokens.IsValidState(new string('a', ApiTokens.MaxStateLength + 1)));
    }

    [Fact]
    public void SanitizeDeviceName_caps_length_without_splitting_a_surrogate_pair()
    {
        Assert.Equal(100, ApiTokens.SanitizeDeviceName(new string('a', 300)).Length);

        var name = ApiTokens.SanitizeDeviceName(new string('a', 99) + "\U0001F600" + "tail");
        Assert.Equal(new string('a', 99), name);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/connect/authorize?client_id=agora-capture&redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback")]
    [InlineData("/account/settings")]
    public void LocalUrls_accepts_site_paths(string url) => Assert.True(LocalUrls.IsLocal(url));

    [Theory]
    [InlineData("//evil.com")]
    [InlineData("/\\evil.com")]
    [InlineData("/x\\y")]
    [InlineData("https://evil.com/")]
    [InlineData("evil.com")]
    [InlineData("javascript:alert(1)")]
    [InlineData("/foo\r\nLocation: https://evil.com")]
    [InlineData("/foo bar")]
    [InlineData("/\tevil")]
    [InlineData("")]
    [InlineData(null)]
    public void LocalUrls_rejects_other_targets(string? url)
    {
        Assert.False(LocalUrls.IsLocal(url));
        Assert.Equal("/", LocalUrls.OrDefault(url));
    }

    [Theory]
    [InlineData("capture.png", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0 }, true)]
    [InlineData("CAPTURE.PNG", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, true)]
    [InlineData("capture.jpg", new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }, true)]
    [InlineData("capture.jpeg", new byte[] { 0xFF, 0xD8, 0xFF, 0xE1 }, true)]
    [InlineData("capture.png", new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }, false)]
    [InlineData("capture.jpg", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, false)]
    [InlineData("capture.gif", new byte[] { 0x47, 0x49, 0x46, 0x38 }, false)]
    [InlineData("capture.html", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, false)]
    [InlineData("capture.png", new byte[] { 0x89, 0x50 }, false)]
    [InlineData("capture", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, false)]
    public void CaptureImages_requires_extension_and_signature_to_agree(string fileName, byte[] header, bool expected) =>
        Assert.Equal(expected, CaptureImages.Matches(fileName, header));
}
