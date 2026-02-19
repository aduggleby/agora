using Agora.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Agora.Infrastructure.Persistence;

/// <summary>
/// EF Core database context for Agora runtime entities, including shares, uploaded-file metadata, and account settings.
/// </summary>
public sealed class AgoraDbContext(DbContextOptions<AgoraDbContext> options) : DbContext(options)
{
    public DbSet<Share> Shares => Set<Share>();
    public DbSet<ShareFile> ShareFiles => Set<ShareFile>();
    public DbSet<DownloadEvent> DownloadEvents => Set<DownloadEvent>();
    public DbSet<AccountTemplate> AccountTemplates => Set<AccountTemplate>();
    public DbSet<UserAccount> Users => Set<UserAccount>();
    public DbSet<SystemSetting> SystemSettings => Set<SystemSetting>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Share>(builder =>
        {
            builder.HasKey(x => x.Id);
            // ShareToken is now the canonical lookup key for public links.
            builder.HasIndex(x => x.ShareToken).IsUnique();
            builder.Property(x => x.UploaderEmail).HasMaxLength(320);
            builder.Property(x => x.ShareToken).HasMaxLength(120);
            builder.Property(x => x.NotifyMode).HasMaxLength(20);
            builder.Property(x => x.SenderName).HasMaxLength(200);
            builder.Property(x => x.SenderEmail).HasMaxLength(320);
            builder.Property(x => x.ZipDisplayName).HasMaxLength(255);
            builder.Property(x => x.ShareExperienceType).HasMaxLength(32);
            builder.Property(x => x.AccessMode).HasMaxLength(32);
            builder.Property(x => x.ContentRootPath).HasMaxLength(400);
            builder.Property(x => x.DownloadPasswordHash).HasMaxLength(1000);
            builder.Property(x => x.PageBackgroundColorHex).HasMaxLength(16);
            builder.Property(x => x.PageContainerPosition).HasMaxLength(32);
        });

        modelBuilder.Entity<ShareFile>(builder =>
        {
            builder.HasKey(x => x.Id);
            builder.Property(x => x.OriginalFilename).HasMaxLength(255);
            builder.Property(x => x.StoredRelativePath).HasMaxLength(400);
            builder.Property(x => x.RenderType).HasMaxLength(32);
            builder.Property(x => x.DetectedContentType).HasMaxLength(150);
        });

        modelBuilder.Entity<DownloadEvent>(builder =>
        {
            builder.HasKey(x => x.Id);
            builder.Property(x => x.IpAddress).HasMaxLength(64);
        });

        modelBuilder.Entity<AccountTemplate>(builder =>
        {
            builder.HasKey(x => x.Id);
            builder.HasIndex(x => x.UploaderEmail).IsUnique();
            builder.Property(x => x.UploaderEmail).HasMaxLength(320);
            builder.Property(x => x.BackgroundColorHex).HasMaxLength(16);
            builder.Property(x => x.ContainerPosition).HasMaxLength(32);
        });

        modelBuilder.Entity<UserAccount>(builder =>
        {
            builder.HasKey(x => x.Id);
            builder.HasIndex(x => x.Email).IsUnique();
            builder.HasIndex(x => x.UploadToken).IsUnique();
            builder.Property(x => x.Email).HasMaxLength(320);
            builder.Property(x => x.UploadToken).HasMaxLength(120);
            builder.Property(x => x.PasswordHash).HasMaxLength(1000);
            builder.Property(x => x.Role).HasMaxLength(20);
            builder.Property(x => x.DefaultNotifyMode).HasMaxLength(20);
            builder.Property(x => x.DefaultExpiryMode).HasMaxLength(20);
            builder.Property(x => x.EmailConfirmationTokenHash).HasMaxLength(64);
            builder.Property(x => x.PendingEmail).HasMaxLength(320);
            builder.Property(x => x.PendingEmailTokenHash).HasMaxLength(64);
            builder.Property(x => x.PendingPasswordHash).HasMaxLength(1000);
            builder.Property(x => x.PendingPasswordTokenHash).HasMaxLength(64);
            builder.Property(x => x.PasswordResetTokenHash).HasMaxLength(64);
            builder.Property(x => x.FailedLoginCount).HasDefaultValue(0);
        });

        modelBuilder.Entity<SystemSetting>(builder =>
        {
            builder.HasKey(x => x.Key);
            builder.Property(x => x.Key).HasMaxLength(120);
            builder.Property(x => x.Value).HasMaxLength(4000);
        });
    }
}
