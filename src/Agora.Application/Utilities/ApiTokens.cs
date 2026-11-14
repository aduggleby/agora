using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Agora.Application.Utilities;

/// <summary>
/// Primitives of the app sign-in flow (OAuth 2.0 authorization code with PKCE, RFC 7636, and a loopback redirect,
/// RFC 8252): bearer tokens and authorization codes, their SHA-256 hashes, the S256 check and the input rules for
/// redirect URIs and device names. Unlike share tokens, codes and tokens are only ever stored hashed.
/// </summary>
public static partial class ApiTokens
{
    /// <summary>The only client: the capture app. There is no client registration.</summary>
    public const string CaptureClientId = "agora-capture";
    /// <summary>Client id stored on tokens created by the owner in Settings for headless agents.</summary>
    public const string AgentClientId = "agora-agent";
    public const string TokenPrefix = "agora_pat_";
    public const string CodeChallengeMethod = "S256";
    public const int DisplayPrefixLength = 8;
    public const int MaxDeviceNameLength = 100;
    public const string DefaultDeviceName = "Unknown device";
    /// <summary>Upper bound of the app's <c>state</c> value, which the consent page echoes back unchanged.</summary>
    public const int MaxStateLength = 512;
    /// <summary>Upper bound of the raw <c>device_name</c> before it is sanitized to <see cref="MaxDeviceNameLength"/>.</summary>
    public const int MaxRawDeviceNameLength = 200;

    /// <summary>Access levels of agent tokens. The capture app has none (null on the row, <see cref="Capture"/> in the claim).</summary>
    public static class AccessLevels
    {
        /// <summary>The claim value of capture app tokens; never stored.</summary>
        public const string Capture = "capture";
        /// <summary>Only shares the token created.</summary>
        public const string Own = "own";
        /// <summary>Every share of the account.</summary>
        public const string All = "all";

        public static bool IsAgentLevel(string? value) => value is Own or All;

        /// <summary>The level when valid, else <see cref="Own"/> (the safe default).</summary>
        public static string NormalizeOrOwn(string? value) => IsAgentLevel(value) ? value! : Own;
    }

    /// <summary>A new bearer token: <see cref="TokenPrefix"/> plus 32 random bytes, base64url.</summary>
    public static string NewToken() => TokenPrefix + TokenCodec.GenerateToken();

    /// <summary>A new authorization code: 32 random bytes, base64url.</summary>
    public static string NewCode() => TokenCodec.GenerateToken();

    /// <summary>Lower-case hex SHA-256, the stored form of codes and tokens.</summary>
    public static string Hash(string value) => TokenCodec.HashToken(value);

    /// <summary>The characters after <see cref="TokenPrefix"/> that identify a token in the Settings list.</summary>
    public static string DisplayPrefix(string token)
    {
        var secret = token.StartsWith(TokenPrefix, StringComparison.Ordinal) ? token[TokenPrefix.Length..] : token;
        return secret.Length <= DisplayPrefixLength ? secret : secret[..DisplayPrefixLength];
    }

    /// <summary>True for a value shaped like a token this server issues (prefix plus 43 base64url characters).</summary>
    public static bool IsWellFormedToken(string? value) => value is not null && TokenFormat().IsMatch(value);

    /// <summary>
    /// An OAuth <c>state</c> value (RFC 6749 VSCHAR): 1 to <see cref="MaxStateLength"/> printable ASCII characters,
    /// so it can be echoed into a redirect without surprises.
    /// </summary>
    public static bool IsValidState(string? state)
    {
        if (string.IsNullOrEmpty(state) || state.Length > MaxStateLength)
        {
            return false;
        }

        foreach (var ch in state)
        {
            if (ch is < ' ' or > '~')
            {
                return false;
            }
        }

        return true;
    }

    public static bool IsSupportedChallengeMethod(string? method) => string.Equals(method, CodeChallengeMethod, StringComparison.Ordinal);

    /// <summary>An S256 challenge: base64url of a SHA-256 digest, 43 characters without padding.</summary>
    public static bool IsValidCodeChallenge(string? challenge) => challenge is not null && ChallengeFormat().IsMatch(challenge);

    /// <summary>A PKCE code verifier (RFC 7636 section 4.1): 43 to 128 unreserved characters.</summary>
    public static bool IsValidCodeVerifier(string? verifier) => verifier is not null && VerifierFormat().IsMatch(verifier);

    /// <summary>The S256 challenge of <paramref name="verifier"/>: base64url(SHA-256(ASCII(verifier))).</summary>
    public static string S256Challenge(string verifier)
    {
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(digest).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>True when <paramref name="verifier"/> is well formed and its S256 challenge equals the stored one (fixed-time).</summary>
    public static bool VerifyPkce(string? verifier, string? challenge)
    {
        if (!IsValidCodeVerifier(verifier) || !IsValidCodeChallenge(challenge))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(S256Challenge(verifier!)),
            Encoding.ASCII.GetBytes(challenge!));
    }

    /// <summary>
    /// Only <c>http://127.0.0.1:&lt;port&gt;/callback</c> or <c>http://[::1]:&lt;port&gt;/callback</c> with a port in
    /// 1024-65535, matched as a literal string: no other host (not even <c>localhost</c>), scheme or path, no userinfo,
    /// query or fragment. The value at exchange must then equal this one byte for byte.
    /// </summary>
    public static bool IsValidRedirectUri(string? redirectUri)
    {
        if (redirectUri is null)
        {
            return false;
        }

        var match = RedirectUriFormat().Match(redirectUri);
        return match.Success &&
               int.TryParse(match.Groups["port"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) &&
               port is >= 1024 and <= 65535;
    }

    /// <summary>
    /// The device name as shown on the consent page and in Settings: control and format characters (including bidi
    /// overrides) removed, trimmed, at most <see cref="MaxDeviceNameLength"/> characters; <see cref="DefaultDeviceName"/>
    /// when nothing is left.
    /// </summary>
    public static string SanitizeDeviceName(string? raw)
    {
        var builder = new StringBuilder((raw ?? string.Empty).Length);
        foreach (var ch in raw ?? string.Empty)
        {
            if (char.IsControl(ch) || CharUnicodeInfo.GetUnicodeCategory(ch) == UnicodeCategory.Format)
            {
                continue;
            }

            builder.Append(ch);
        }

        var name = builder.ToString().Trim();
        if (name.Length > MaxDeviceNameLength)
        {
            var cut = char.IsHighSurrogate(name[MaxDeviceNameLength - 1]) ? MaxDeviceNameLength - 1 : MaxDeviceNameLength;
            name = name[..cut].TrimEnd();
        }

        return name.Length == 0 ? DefaultDeviceName : name;
    }

    [GeneratedRegex(@"^agora_pat_[A-Za-z0-9_-]{43}\z", RegexOptions.CultureInvariant)]
    private static partial Regex TokenFormat();

    [GeneratedRegex(@"^[A-Za-z0-9_-]{43}\z", RegexOptions.CultureInvariant)]
    private static partial Regex ChallengeFormat();

    [GeneratedRegex(@"^[A-Za-z0-9\-._~]{43,128}\z", RegexOptions.CultureInvariant)]
    private static partial Regex VerifierFormat();

    [GeneratedRegex(@"^http://(?:127\.0\.0\.1|\[::1\]):(?<port>[1-9][0-9]{3,4})/callback\z", RegexOptions.CultureInvariant)]
    private static partial Regex RedirectUriFormat();
}
