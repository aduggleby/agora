using Agora.Application.Utilities;
using Agora.Infrastructure.Logging;
using Agora.Infrastructure.Persistence;
using Microsoft.Extensions.Configuration;

namespace Agora.Application.Tests;

/// <summary>
/// Covers startup option parsing: database provider selection, log file settings and email normalization.
/// </summary>
public sealed class StartupOptionsTests
{
    [Theory]
    [InlineData(null, DatabaseProvider.SqlServer)]
    [InlineData("", DatabaseProvider.SqlServer)]
    [InlineData("  ", DatabaseProvider.SqlServer)]
    [InlineData("SqlServer", DatabaseProvider.SqlServer)]
    [InlineData("sqlserver", DatabaseProvider.SqlServer)]
    [InlineData("Postgres", DatabaseProvider.Postgres)]
    [InlineData(" POSTGRES ", DatabaseProvider.Postgres)]
    public void ParseProvider_AcceptsKnownValues(string? value, DatabaseProvider expected)
    {
        Assert.Equal(expected, DatabaseSetup.ParseProvider(value));
    }

    [Theory]
    [InlineData("Sqlite")]
    [InlineData("PostgreSQL")]
    [InlineData("mssql")]
    public void ParseProvider_RejectsUnknownValues(string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => DatabaseSetup.ParseProvider(value));
        Assert.Contains(value, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LogFileOptions_Defaults()
    {
        var options = LogFileOptions.Resolve(Config());

        Assert.Equal(new LogFileOptions(true, "logs", 30), options);
    }

    [Fact]
    public void LogFileOptions_ReadsAgoraSettings()
    {
        Assert.Equal(
            new LogFileOptions(false, "/var/log/agora", 90),
            LogFileOptions.Resolve(Config(("Agora:Logging:File:Enabled", "false"), ("Agora:Logging:File:Path", "/var/log/agora"), ("Agora:Logging:File:RetainedDays", "90"))));
    }

    [Fact]
    public void LogFileOptions_LegacySerilogPathKeepsExistingInstallsInPlace()
    {
        var options = LogFileOptions.Resolve(Config(
            ("Serilog:WriteTo:0:Args:path", "/mnt/tank/agora/logs/agora-.log"),
            ("Agora:Logging:File:Path", "/app/data/logs")));

        Assert.Equal("/mnt/tank/agora/logs", options.Path);
    }

    [Fact]
    public void LogFileOptions_LegacySerilogRetentionWinsAsSerilogWouldApplyIt()
    {
        Assert.Equal(90, LogFileOptions.Resolve(Config(
            ("Serilog:WriteTo:0:Args:retainedFileCountLimit", "90"),
            ("Agora:Logging:File:RetainedDays", "30"))).RetainedDays);
        // Legacy numbers are not capped, only floored at 1.
        Assert.Equal(100000, LogFileOptions.Resolve(Config(("Serilog:WriteTo:0:Args:retainedFileCountLimit", "100000"))).RetainedDays);
        Assert.Equal(1, LogFileOptions.Resolve(Config(("Serilog:WriteTo:0:Args:retainedFileCountLimit", "0"))).RetainedDays);
        Assert.Equal(45, LogFileOptions.Resolve(Config(
            ("Serilog:WriteTo:0:Args:retainedFileCountLimit", "not-a-number"),
            ("Agora:Logging:File:RetainedDays", "45"))).RetainedDays);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData(null)]
    public void LogFileOptions_LegacySerilogRetentionPresentButEmptyMeansUnlimited(string? legacyValue)
    {
        var options = LogFileOptions.Resolve(Config(
            ("Serilog:WriteTo:0:Args:retainedFileCountLimit", legacyValue),
            ("Agora:Logging:File:RetainedDays", "30")));

        Assert.Null(options.RetainedDays);
    }

    [Fact]
    public void LogFileOptions_NewRetentionIsClamped()
    {
        Assert.Equal(1, LogFileOptions.Resolve(Config(("Agora:Logging:File:RetainedDays", "0"))).RetainedDays);
        Assert.Equal(3650, LogFileOptions.Resolve(Config(("Agora:Logging:File:RetainedDays", "99999"))).RetainedDays);
    }

    [Theory]
    [InlineData(" Mixed@Example.COM ", "mixed@example.com")]
    [InlineData(null, "")]
    public void EmailAddress_Normalize_TrimsAndLowercases(string? value, string expected)
    {
        Assert.Equal(expected, EmailAddress.Normalize(value));
    }

    private static IConfiguration Config(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(x => new KeyValuePair<string, string?>(x.Key, x.Value)))
            .Build();
}
