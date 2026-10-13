using Agora.Application.Utilities;
using Agora.Web.Services;

namespace Agora.Application.Tests;

/// <summary>
/// The From display name of outgoing mail may contain uploader-supplied text: it is reduced to printable text without
/// header or address delimiters, capped, and quoted by one builder.
/// </summary>
public sealed class EmailDisplayNameTests
{
    [Fact]
    public void Sanitize_strips_line_breaks_and_other_control_characters()
    {
        Assert.Equal("IT Support bcc victim@example.com", EmailDisplayName.Sanitize("IT Support\r\nbcc: victim@example.com\t\u0000"));
    }

    [Fact]
    public void Sanitize_strips_quotes_backslashes_brackets_and_delimiters()
    {
        Assert.Equal("Alice alice@example.com", EmailDisplayName.Sanitize("\"Alice\" <alice@example.com>, \\ ; :"));
    }

    [Fact]
    public void Sanitize_collapses_whitespace()
    {
        Assert.Equal("Alice B Example", EmailDisplayName.Sanitize("  Alice \t\t B   Example  "));
    }

    [Fact]
    public void Sanitize_caps_at_80_characters()
    {
        var sanitized = EmailDisplayName.Sanitize(new string('a', 300));

        Assert.Equal(80, sanitized.Length);
        Assert.Equal(new string('a', 80), sanitized);
    }

    [Fact]
    public void Sanitize_keeps_emoji_and_never_splits_a_surrogate_pair()
    {
        Assert.Equal("Alice \U0001F600", EmailDisplayName.Sanitize("Alice \U0001F600"));

        // 79 ASCII characters followed by one two-char emoji: the cut would land between the surrogates.
        var sanitized = EmailDisplayName.Sanitize(new string('b', 79) + "\U0001F600");
        Assert.Equal(79, sanitized.Length);
        Assert.DoesNotContain(sanitized, ch => char.IsSurrogate(ch));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\"<>\\,:;\r\n")]
    public void Sanitize_returns_empty_when_nothing_printable_remains(string? value)
    {
        Assert.Equal(string.Empty, EmailDisplayName.Sanitize(value));
    }

    [Fact]
    public void BuildFromHeader_quotes_the_display_name_and_escapes_quotes_and_backslashes()
    {
        Assert.Equal("\"Agora \\\"HQ\\\" \\\\ team\" <no-reply@example.com>", EmailDisplayName.BuildFromHeader("no-reply@example.com", "Agora \"HQ\" \\ team"));
    }

    [Fact]
    public void BuildFromHeader_keeps_emoji_and_angle_brackets_inside_the_quoted_name()
    {
        Assert.Equal("\"Agora \U0001F600 <x>\" <no-reply@example.com>", EmailDisplayName.BuildFromHeader("no-reply@example.com", "Agora \U0001F600 <x>"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void BuildFromHeader_returns_the_bare_address_without_a_display_name(string? displayName)
    {
        Assert.Equal("no-reply@example.com", EmailDisplayName.BuildFromHeader(" no-reply@example.com ", displayName));
    }

    [Theory]
    [InlineData("Agora\r\nBcc: victim@example.com")]
    [InlineData("Agora\nteam")]
    public void BuildFromHeader_rejects_line_breaks_in_the_display_name(string displayName)
    {
        Assert.Throws<ArgumentException>(() => EmailDisplayName.BuildFromHeader("no-reply@example.com", displayName));
    }

    [Theory]
    [InlineData("")]
    [InlineData("no-reply@example.com\r\nBcc: x@example.com")]
    [InlineData("<no-reply@example.com>")]
    [InlineData("a b@example.com")]
    public void BuildFromHeader_rejects_malformed_addresses(string address)
    {
        Assert.Throws<ArgumentException>(() => EmailDisplayName.BuildFromHeader(address, "Agora"));
    }

    [Fact]
    public void On_behalf_of_from_name_is_sanitised_and_capped_while_the_body_keeps_the_full_text()
    {
        var payload = Payload(senderName: "IT \"Support\"\r\nBcc: boss@example.com <evil>" + new string('x', 200), senderEmail: "it@example.com");

        var message = QueuedShareCreationJob.BuildCompletionEmailCore(payload, "https://files.example.com/s/abcdefgh", "owner@example.com", "Agora");

        Assert.NotNull(message.FromDisplayNameOverride);
        Assert.StartsWith("Agora on behalf of IT Support Bcc boss@example.com evil", message.FromDisplayNameOverride);
        Assert.Equal(EmailDisplayName.MaxLength, message.FromDisplayNameOverride!.Length);
        Assert.DoesNotContain(message.FromDisplayNameOverride, ch => ch is '"' or '<' or '>' or ':' or '\r' or '\n');
        Assert.Contains("on behalf of IT \"Support\"", message.SecondaryText);
    }

    [Fact]
    public void On_behalf_of_from_name_falls_back_to_the_configured_name_when_nothing_printable_remains()
    {
        var payload = Payload(senderName: "\"<>\"", senderEmail: null);

        var message = QueuedShareCreationJob.BuildCompletionEmailCore(payload, "https://files.example.com/s/abcdefgh", "owner@example.com", "Agora");

        // A null override makes the sender use the configured display name; the body still names the sender.
        Assert.Null(message.FromDisplayNameOverride);
        Assert.Contains("on behalf of", message.SecondaryText);
    }

    private static QueuedShareCreationJob.Payload Payload(string? senderName, string? senderEmail) => new(
        UploaderEmail: "owner@example.com",
        DraftShareId: Guid.NewGuid().ToString("N"),
        ShareToken: "abcdefgh",
        Message: null,
        SenderName: senderName,
        SenderEmail: senderEmail,
        SenderMessage: "Hello",
        DownloadPassword: null,
        ShowPreviews: false,
        ZipFileName: null,
        NotifyMode: "none",
        ExpiryMode: "days",
        ExpiresAtUtc: null,
        TemplateMode: "account",
        TemplateTitle: null,
        TemplateH1: null,
        TemplateDescription: null,
        TemplateBackgroundColorHex: null,
        TemplateContainerPosition: null,
        TemplateBackgroundUploadId: null,
        UploadedFileIds: []);
}
