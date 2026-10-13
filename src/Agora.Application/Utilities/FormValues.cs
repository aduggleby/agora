namespace Agora.Application.Utilities;

public static class FormValues
{
    /// <summary>
    /// Reads a checkbox posted together with a hidden fallback of the same name (<c>enabled=false</c> followed by
    /// <c>enabled=true</c> when checked). The browser sends both, so the last value wins; anything that is not a
    /// boolean, including no value at all, reads as <c>false</c>.
    /// </summary>
    public static bool LastBool(IEnumerable<string?> values)
    {
        var last = values.LastOrDefault(static v => !string.IsNullOrWhiteSpace(v));
        return bool.TryParse(last, out var parsed) && parsed;
    }
}
