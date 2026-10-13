namespace Agora.Application.Models;

/// <summary>
/// The fixed set of lifetimes a temporary direct link can have. Anything else on the wire is refused.
/// </summary>
public enum DirectLinkDuration
{
    ThirtyMinutes,
    SixHours,
    OneDay,
    SevenDays
}

public static class DirectLinkDurations
{
    public const string DefaultWireValue = "1d";

    public static readonly IReadOnlyList<DirectLinkDuration> All =
    [
        DirectLinkDuration.ThirtyMinutes,
        DirectLinkDuration.SixHours,
        DirectLinkDuration.OneDay,
        DirectLinkDuration.SevenDays
    ];

    /// <summary>Parses the wire value (<c>30m</c>, <c>6h</c>, <c>1d</c>, <c>7d</c>); whitespace and case are ignored.</summary>
    public static bool TryParse(string? raw, out DirectLinkDuration duration)
    {
        switch (raw?.Trim().ToLowerInvariant())
        {
            case "30m":
                duration = DirectLinkDuration.ThirtyMinutes;
                return true;
            case "6h":
                duration = DirectLinkDuration.SixHours;
                return true;
            case "1d":
                duration = DirectLinkDuration.OneDay;
                return true;
            case "7d":
                duration = DirectLinkDuration.SevenDays;
                return true;
            default:
                duration = DirectLinkDuration.OneDay;
                return false;
        }
    }

    public static string ToWireValue(DirectLinkDuration duration) => duration switch
    {
        DirectLinkDuration.ThirtyMinutes => "30m",
        DirectLinkDuration.SixHours => "6h",
        DirectLinkDuration.SevenDays => "7d",
        _ => "1d"
    };

    public static TimeSpan ToTimeSpan(DirectLinkDuration duration) => duration switch
    {
        DirectLinkDuration.ThirtyMinutes => TimeSpan.FromMinutes(30),
        DirectLinkDuration.SixHours => TimeSpan.FromHours(6),
        DirectLinkDuration.SevenDays => TimeSpan.FromDays(7),
        _ => TimeSpan.FromDays(1)
    };
}
