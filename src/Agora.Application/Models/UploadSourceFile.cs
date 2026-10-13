namespace Agora.Application.Models;

public sealed record UploadSourceFile(
    string TempPath,
    string OriginalFileName,
    long OriginalSizeBytes,
    string ContentType);
