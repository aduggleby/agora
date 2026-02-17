using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class TokenCodecTests
{
    [Fact]
    public void HashIsDeterministic()
    {
        var a = TokenCodec.HashToken("abc");
        var b = TokenCodec.HashToken("abc");
        Assert.Equal(a, b);
    }

    [Fact]
    public void PrefixUsesEightCharacters()
    {
        var prefix = TokenCodec.TokenPrefix("1234567890");
        Assert.Equal("12345678", prefix);
    }
}
