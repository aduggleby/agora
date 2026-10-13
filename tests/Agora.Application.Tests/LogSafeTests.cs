using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class LogSafeTests
{
    [Theory]
    [InlineData("abcd1234")]
    [InlineData("Ab3xYz9Q")]
    [InlineData("0123456789abcdef0123456789abcdef")]
    [InlineData("a-very-long-share-token-with-dashes_and_underscores-0123456789")]
    public void Token_NeverReturnsOrContainsTheInput(string token)
    {
        var reference = LogSafe.Token(token);

        Assert.NotEqual(token, reference);
        Assert.DoesNotContain(token, reference, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("tok:", reference, StringComparison.Ordinal);
        Assert.Equal(reference, LogSafe.Token(token));
    }

    [Fact]
    public void Token_HandlesMissingValues()
    {
        Assert.Equal("(none)", LogSafe.Token(null));
        Assert.Equal("(none)", LogSafe.Token(string.Empty));
    }

    [Fact]
    public void Token_DistinguishesDifferentTokens()
    {
        Assert.NotEqual(LogSafe.Token("abcdefgh"), LogSafe.Token("abcdefgi"));
    }
}
