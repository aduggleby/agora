using Agora.Application.Utilities;
using Serilog.Core;
using Serilog.Events;

namespace Agora.Web.Startup;

/// <summary>
/// Last line of defence at the logging boundary: every string property of a log event (request paths, query strings,
/// redirect locations, structured arguments) has share/upload/confirmation tokens replaced by their log reference.
/// </summary>
public sealed class TokenRedactionEnricher : ILogEventEnricher
{
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        foreach (var (name, value) in logEvent.Properties.ToList())
        {
            if (value is not ScalarValue { Value: string text })
            {
                continue;
            }

            var redacted = TokenRedaction.Redact(text);
            if (!ReferenceEquals(redacted, text) && !string.Equals(redacted, text, StringComparison.Ordinal))
            {
                logEvent.AddOrUpdateProperty(propertyFactory.CreateProperty(name, redacted));
            }
        }
    }
}
