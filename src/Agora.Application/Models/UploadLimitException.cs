namespace Agora.Application.Models;

public enum UploadLimitKind
{
    /// <summary>Per-draft file count reached (HTTP 400).</summary>
    TooManyFiles,
    /// <summary>Per-draft total bytes reached (HTTP 413).</summary>
    TooManyBytes,
    /// <summary>Open-draft cap per upload code or client address reached (HTTP 429).</summary>
    TooManyOpenDrafts,
    /// <summary>Daily received-share quota of the upload code reached (HTTP 429).</summary>
    DailyQuotaExceeded,
    /// <summary>The draft was already submitted; nothing can be staged into it any more (HTTP 409).</summary>
    DraftSealed,
    /// <summary>The draft no longer exists (finalized or swept) or belongs to someone else (HTTP 409).</summary>
    DraftClosed,
    /// <summary>The background queue refused the job; the submission can be retried (HTTP 503).</summary>
    QueueUnavailable,
    /// <summary>Scratch area full or volume below the free-space floor (HTTP 507).</summary>
    InsufficientStorage
}

/// <summary>
/// An upload was refused because a configured budget is exhausted. The message is safe to return to the client.
/// </summary>
public sealed class UploadLimitException(UploadLimitKind kind, string message) : Exception(message)
{
    public UploadLimitKind Kind { get; } = kind;

    public int StatusCode => Kind switch
    {
        UploadLimitKind.TooManyFiles => 400,
        UploadLimitKind.TooManyBytes => 413,
        UploadLimitKind.TooManyOpenDrafts => 429,
        UploadLimitKind.DailyQuotaExceeded => 429,
        UploadLimitKind.DraftSealed => 409,
        UploadLimitKind.DraftClosed => 409,
        UploadLimitKind.QueueUnavailable => 503,
        UploadLimitKind.InsufficientStorage => 507,
        _ => 400
    };
}
