using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class SenderFieldsTests
{
    [Theory]
    [InlineData("  Ada   Lovelace ", "Ada Lovelace")]
    [InlineData("Ada\tLovelace\r\nSmith", "Ada Lovelace Smith")]
    [InlineData("Ada\u0000Love\u0007lace", "AdaLovelace")]
    [InlineData("   ", "")]
    [InlineData(null, "")]
    public void NormalizeText_StripsControlCharactersAndCollapsesWhitespace(string? raw, string expected)
    {
        Assert.Equal(expected, SenderFields.NormalizeText(raw));
    }

    [Theory]
    [InlineData("ada@example.com", true)]
    [InlineData(" ada@example.com ", true)]
    [InlineData("Ada@Example.com", true)]
    [InlineData("Ada <ada@example.com>", false)]
    [InlineData("ada", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsValidEmailAddress_AcceptsOnlyBareAddresses(string? value, bool expected)
    {
        Assert.Equal(expected, SenderFields.IsValidEmailAddress(value));
    }
}
