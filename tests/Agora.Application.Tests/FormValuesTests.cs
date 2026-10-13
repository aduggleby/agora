using Agora.Application.Utilities;
using Microsoft.Extensions.Primitives;

namespace Agora.Application.Tests;

public sealed class FormValuesTests
{
    [Fact]
    public void LastBool_CheckedBoxAfterHiddenFallbackIsTrue()
    {
        // A hidden enabled=false precedes the checkbox enabled=true, so the browser posts both.
        Assert.True(FormValues.LastBool(new StringValues(["false", "true"])));
    }

    [Fact]
    public void LastBool_UncheckedBoxLeavesOnlyTheHiddenFalse()
    {
        Assert.False(FormValues.LastBool(new StringValues("false")));
    }

    [Fact]
    public void LastBool_SingleValues()
    {
        Assert.True(FormValues.LastBool(new StringValues("true")));
        Assert.True(FormValues.LastBool(new StringValues("True")));
        Assert.False(FormValues.LastBool(StringValues.Empty));
        Assert.False(FormValues.LastBool(new StringValues("on")));
    }

    [Fact]
    public void LastBool_IgnoresTrailingBlanksAndRejectsGarbage()
    {
        Assert.True(FormValues.LastBool(["false", "true", ""]));
        Assert.False(FormValues.LastBool(["false", "x"]));
        Assert.False(FormValues.LastBool(["true", "false"]));
    }
}
