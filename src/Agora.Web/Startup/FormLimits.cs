using Microsoft.AspNetCore.Http.Features;

namespace Agora.Web.Startup;

/// <summary>
/// App-wide request body and form limits. Every endpoint (and the antiforgery form fallback) gets these small limits;
/// only the upload endpoints raise them, per endpoint (<c>RequestSizeLimit</c>) and per call
/// (<see cref="Agora.Web.Endpoints.UploadStagingEndpoints.UploadFormOptions"/>), after their admission checks.
/// </summary>
public static class FormLimits
{
    /// <summary>Kestrel's global request body limit and the default multipart section limit: 1 MiB.</summary>
    public const long DefaultMaxRequestBodyBytes = 1024 * 1024;

    public const int ValueLengthLimit = 64 * 1024;

    public const int ValueCountLimit = 1024;

    public static void Configure(FormOptions options)
    {
        options.MultipartBodyLengthLimit = DefaultMaxRequestBodyBytes;
        options.BufferBodyLengthLimit = DefaultMaxRequestBodyBytes;
        options.ValueLengthLimit = ValueLengthLimit;
        options.ValueCountLimit = ValueCountLimit;
    }
}
