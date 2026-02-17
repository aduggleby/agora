using Agora.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Agora.Infrastructure.Persistence;

public sealed class AgoraDbContext(DbContextOptions<AgoraDbContext> options) : DbContext(options)
{
    public DbSet<Share> Shares => Set<Share>();
    public DbSet<ShareFile> ShareFiles => Set<ShareFile>();
    public DbSet<DownloadEvent> DownloadEvents => Set<DownloadEvent>();
    public DbSet<AccountTemplate> AccountTemplates => Set<AccountTemplate>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Share>(builder =>
        {
            builder.HasKey(x => x.Id);
            builder.HasIndex(x => x.ShareTokenHash).IsUnique();
            builder.Property(x => x.UploaderEmail).HasMaxLength(320);
            builder.Property(x => x.NotifyMode).HasMaxLength(20);
            builder.Property(x => x.ZipDisplayName).HasMaxLength(255);
            builder.Property(x => x.ShareTokenPrefix).HasMaxLength(16);
        });

        modelBuilder.Entity<ShareFile>(builder =>
        {
            builder.HasKey(x => x.Id);
            builder.Property(x => x.OriginalFilename).HasMaxLength(255);
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
        });
    }
}
