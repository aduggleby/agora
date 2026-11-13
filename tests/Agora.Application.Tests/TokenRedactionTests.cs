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
    [InlineData("/S/Ab12cd34", "/S/")]
    [InlineData("/U/Ab12cd34Ef", "/U/")]
    [InlineData("/api/shares/Ab12cd34", "/api/shares/")]
    [InlineData("/api/shares/Ab12cd34/status", "/api/shares/")]
    [InlineData("/API/Shares/Ab12cd34/status", "/API/Shares/")]
    [InlineData("/api/v1/shares/Ab12cd34", "/api/v1/shares/")]
    [InlineData("/confirm-email-required?email=a%40b.c&gate=Ab12cd34", "gate=")]
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
    [InlineData("Authorization: Bearer agora_pat_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "agora_pat_")]
    [InlineData("http://127.0.0.1:5000/callback?code=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&state=s", "code=")]
    [InlineData("?code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "code_verifier=")]
    [InlineData("{\"code\": \"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\"}", "\"code\": \"")]
    [InlineData("{\"code_verifier\":\"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\"}", "\"code_verifier\":\"")]
    [InlineData("{\"access_token\":\"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\"}", "\"access_token\":\"")]
    public void Redact_ReplacesApiTokensCodesAndVerifiers(string input, string keptPrefix)
    {
        var redacted = TokenRedaction.Redact(input);

        Assert.DoesNotContain("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", redacted);
        Assert.Contains(keptPrefix + "tok:", redacted);
        Assert.Equal(redacted, TokenRedaction.Redact(redacted));
    }

    [Theory]
    [InlineData("?code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")]
    [InlineData("error_code=42")]
    [InlineData("/connect/authorize?client_id=agora-capture&state=abc")]
    public void Redact_LeavesNonSecretOAuthParametersAlone(string input)
    {
        Assert.Equal(input, TokenRedaction.Redact(input));
    }

    [Theory]
    [InlineData("/js/app.js")]
    [InlineData("/account/settings?msg=Template%20saved")]
    [InlineData("limit=5&count=2")]
    [InlineData("/api/shares")]
    [InlineData("/api/shares/direct-link")]
    [InlineData("/api/shares/direct-link?x=1")]
    [InlineData("/api/shares/tok:abc")]
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
