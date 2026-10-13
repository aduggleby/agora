using Agora.Application.Utilities;
using Agora.Web.Startup;
using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;

namespace Agora.Application.Tests;

public sealed class TokenRedactionTests
{
    [Theory]
    [InlineData("/s/Ab12cd34", "/s/")]
    [InlineData("/s/Ab12cd34/download", "/s/")]
    [InlineData("/u/Ab12cd34Ef", "/u/")]
    [InlineData("/shares/created/Ab12cd34", "/shares/created/")]
    [InlineData("?token=Ab12cd34&x=1", "token=")]
    [InlineData("/auth/confirm-email?email=a%40b.c&token=Zz9-yy_8", "token=")]
    [InlineData("https://files.example.com/reset-password?email=a&t=abcdefgh", "t=")]
    [InlineData("uploadToken=AbCdEfGh12", "uploadToken=")]
    public void Redact_ReplacesTokensWithTheirLogReference(string input, string keptPrefix)
    {
        var redacted = TokenRedaction.Redact(input);

        Assert.NotEqual(input, redacted);
        Assert.Contains(keptPrefix + "tok:", redacted);
        Assert.DoesNotContain("Ab12cd34", redacted);
        Assert.DoesNotContain("Zz9-yy_8", redacted);
        Assert.DoesNotContain("abcdefgh", redacted);
        Assert.DoesNotContain("AbCdEfGh12", redacted);
        Assert.Equal(redacted, TokenRedaction.Redact(redacted));
    }

    [Theory]
    [InlineData("/js/app.js")]
    [InlineData("/account/settings?msg=Template%20saved")]
    [InlineData("limit=5&count=2")]
    [InlineData("/api/shares")]
    [InlineData("")]
    public void Redact_LeavesOtherTextAlone(string input)
    {
        Assert.Equal(input, TokenRedaction.Redact(input));
    }

    [Fact]
    public void Enricher_RedactsEveryStringPropertyOfAnEvent()
    {
        var template = new MessageTemplateParser().Parse("Request {RequestPath}{QueryString} redirected to {Location}; share {Token}");
        var logEvent = new LogEvent(
            DateTimeOffset.UtcNow,
            LogEventLevel.Information,
            null,
            template,
            [
                new LogEventProperty("RequestPath", new ScalarValue("/s/Ab12cd34/download")),
                new LogEventProperty("QueryString", new ScalarValue("?token=Zz9-yy_8")),
                new LogEventProperty("Location", new ScalarValue("/shares/created/Ab12cd34")),
                new LogEventProperty("Token", new ScalarValue("Ab12cd34")),
                new LogEventProperty("Count", new ScalarValue(3)),
            ]);

        new TokenRedactionEnricher().Enrich(logEvent, new PropertyFactory());
        var rendered = logEvent.RenderMessage();

        Assert.DoesNotContain("Zz9-yy_8", rendered);
        Assert.Equal("/s/" + LogSafe.Token("Ab12cd34") + "/download", ((ScalarValue)logEvent.Properties["RequestPath"]).Value);
        Assert.Equal("?token=" + LogSafe.Token("Zz9-yy_8"), ((ScalarValue)logEvent.Properties["QueryString"]).Value);
        Assert.Equal("/shares/created/" + LogSafe.Token("Ab12cd34"), ((ScalarValue)logEvent.Properties["Location"]).Value);
        // A bare token in a property is not recognisable as such; callers use LogSafe.Token for those.
        Assert.Equal(3, ((ScalarValue)logEvent.Properties["Count"]).Value);
    }

    private sealed class PropertyFactory : ILogEventPropertyFactory
    {
        public LogEventProperty CreateProperty(string name, object? value, bool destructureObjects = false) =>
            new(name, new ScalarValue(value));
    }
}
