namespace Agora.Application.Models;

public sealed record CreateShareResult(Guid ShareId, string Token, string ZipDisplayName, DateTime? ExpiresAtUtc);
