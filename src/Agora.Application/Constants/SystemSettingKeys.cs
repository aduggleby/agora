namespace Agora.Application.Constants;

public static class SystemSettingKeys
{
    public const string AllowRegistration = "auth.allow_registration";
    /// <summary>Set once the one-time owner-id backfill of shares and templates has run; it never runs again.</summary>
    public const string OwnershipBackfillCompletedAt = "ownership.backfill_completed_at";
}
