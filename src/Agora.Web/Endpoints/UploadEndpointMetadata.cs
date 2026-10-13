namespace Agora.Web.Endpoints;

/// <summary>
/// Marks the endpoints that take uploads or submit drafts. The CSRF middleware keys on this (not on path strings, which
/// a trailing slash or case change would slip past): when <see cref="RequiresHeaderCsrfToken"/> is set the token must
/// arrive in the X-CSRF-TOKEN header, so antiforgery never has to buffer a multipart body to find it.
/// </summary>
public sealed record UploadEndpointMetadata(bool RequiresHeaderCsrfToken);
