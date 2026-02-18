using Agora.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using System.Data;

namespace Agora.Web.Startup;

public static class SchemaUpgradeRunner
{
    public static async Task EnsureSchemaUpgradesAsync(AgoraDbContext db, CancellationToken cancellationToken)
    {
        if (db.Database.IsSqlite())
        {
            var hasDefaultNotifyMode = await SqliteColumnExistsAsync(db, "Users", "DefaultNotifyMode", cancellationToken);
            if (!hasDefaultNotifyMode)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "DefaultNotifyMode" TEXT NOT NULL DEFAULT 'once'""",
                    cancellationToken);
            }
    
            var hasDefaultExpiryMode = await SqliteColumnExistsAsync(db, "Users", "DefaultExpiryMode", cancellationToken);
            if (!hasDefaultExpiryMode)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "DefaultExpiryMode" TEXT NOT NULL DEFAULT '7_days'""",
                    cancellationToken);
            }
    
            var hasFailedLoginCount = await SqliteColumnExistsAsync(db, "Users", "FailedLoginCount", cancellationToken);
            if (!hasFailedLoginCount)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "FailedLoginCount" INTEGER NOT NULL DEFAULT 0""",
                    cancellationToken);
            }
    
            var hasLastFailedLoginAtUtc = await SqliteColumnExistsAsync(db, "Users", "LastFailedLoginAtUtc", cancellationToken);
            if (!hasLastFailedLoginAtUtc)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "LastFailedLoginAtUtc" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasLockoutEndUtc = await SqliteColumnExistsAsync(db, "Users", "LockoutEndUtc", cancellationToken);
            if (!hasLockoutEndUtc)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "LockoutEndUtc" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasEmailConfirmed = await SqliteColumnExistsAsync(db, "Users", "EmailConfirmed", cancellationToken);
            if (!hasEmailConfirmed)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "EmailConfirmed" INTEGER NOT NULL DEFAULT 1""",
                    cancellationToken);
            }
    
            var hasEmailConfirmedAtUtc = await SqliteColumnExistsAsync(db, "Users", "EmailConfirmedAtUtc", cancellationToken);
            if (!hasEmailConfirmedAtUtc)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "EmailConfirmedAtUtc" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasEmailConfirmationTokenHash = await SqliteColumnExistsAsync(db, "Users", "EmailConfirmationTokenHash", cancellationToken);
            if (!hasEmailConfirmationTokenHash)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "EmailConfirmationTokenHash" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasEmailConfirmationTokenExpiresAtUtc = await SqliteColumnExistsAsync(db, "Users", "EmailConfirmationTokenExpiresAtUtc", cancellationToken);
            if (!hasEmailConfirmationTokenExpiresAtUtc)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "EmailConfirmationTokenExpiresAtUtc" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasPendingEmail = await SqliteColumnExistsAsync(db, "Users", "PendingEmail", cancellationToken);
            if (!hasPendingEmail)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "PendingEmail" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasPendingEmailTokenHash = await SqliteColumnExistsAsync(db, "Users", "PendingEmailTokenHash", cancellationToken);
            if (!hasPendingEmailTokenHash)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "PendingEmailTokenHash" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasPendingEmailTokenExpiresAtUtc = await SqliteColumnExistsAsync(db, "Users", "PendingEmailTokenExpiresAtUtc", cancellationToken);
            if (!hasPendingEmailTokenExpiresAtUtc)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "PendingEmailTokenExpiresAtUtc" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasPendingPasswordHash = await SqliteColumnExistsAsync(db, "Users", "PendingPasswordHash", cancellationToken);
            if (!hasPendingPasswordHash)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "PendingPasswordHash" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasPendingPasswordTokenHash = await SqliteColumnExistsAsync(db, "Users", "PendingPasswordTokenHash", cancellationToken);
            if (!hasPendingPasswordTokenHash)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "PendingPasswordTokenHash" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasPendingPasswordTokenExpiresAtUtc = await SqliteColumnExistsAsync(db, "Users", "PendingPasswordTokenExpiresAtUtc", cancellationToken);
            if (!hasPendingPasswordTokenExpiresAtUtc)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "PendingPasswordTokenExpiresAtUtc" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasPasswordResetTokenHash = await SqliteColumnExistsAsync(db, "Users", "PasswordResetTokenHash", cancellationToken);
            if (!hasPasswordResetTokenHash)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "PasswordResetTokenHash" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasPasswordResetTokenExpiresAtUtc = await SqliteColumnExistsAsync(db, "Users", "PasswordResetTokenExpiresAtUtc", cancellationToken);
            if (!hasPasswordResetTokenExpiresAtUtc)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Users" ADD COLUMN "PasswordResetTokenExpiresAtUtc" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasAccountTemplateBackgroundColor = await SqliteColumnExistsAsync(db, "AccountTemplates", "BackgroundColorHex", cancellationToken);
            if (!hasAccountTemplateBackgroundColor)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "AccountTemplates" ADD COLUMN "BackgroundColorHex" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasAccountTemplateContainerPosition = await SqliteColumnExistsAsync(db, "AccountTemplates", "ContainerPosition", cancellationToken);
            if (!hasAccountTemplateContainerPosition)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "AccountTemplates" ADD COLUMN "ContainerPosition" TEXT NOT NULL DEFAULT 'center'""",
                    cancellationToken);
            }
    
            var hasShareBackgroundColor = await SqliteColumnExistsAsync(db, "Shares", "PageBackgroundColorHex", cancellationToken);
            if (!hasShareBackgroundColor)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Shares" ADD COLUMN "PageBackgroundColorHex" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasShareContainerPosition = await SqliteColumnExistsAsync(db, "Shares", "PageContainerPosition", cancellationToken);
            if (!hasShareContainerPosition)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Shares" ADD COLUMN "PageContainerPosition" TEXT NOT NULL DEFAULT 'center'""",
                    cancellationToken);
            }
    
            var hasShareToken = await SqliteColumnExistsAsync(db, "Shares", "ShareToken", cancellationToken);
            if (!hasShareToken)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Shares" ADD COLUMN "ShareToken" TEXT NOT NULL DEFAULT ''""",
                    cancellationToken);
            }
    
            var hasShareDownloadPasswordHash = await SqliteColumnExistsAsync(db, "Shares", "DownloadPasswordHash", cancellationToken);
            if (!hasShareDownloadPasswordHash)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Shares" ADD COLUMN "DownloadPasswordHash" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasShareExperienceType = await SqliteColumnExistsAsync(db, "Shares", "ShareExperienceType", cancellationToken);
            if (!hasShareExperienceType)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Shares" ADD COLUMN "ShareExperienceType" TEXT NOT NULL DEFAULT 'archive'""",
                    cancellationToken);
            }
    
            var hasShareAccessMode = await SqliteColumnExistsAsync(db, "Shares", "AccessMode", cancellationToken);
            if (!hasShareAccessMode)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Shares" ADD COLUMN "AccessMode" TEXT NOT NULL DEFAULT 'download_only'""",
                    cancellationToken);
            }
    
            var hasShareContentRootPath = await SqliteColumnExistsAsync(db, "Shares", "ContentRootPath", cancellationToken);
            if (!hasShareContentRootPath)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "Shares" ADD COLUMN "ContentRootPath" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasShareFileStoredRelativePath = await SqliteColumnExistsAsync(db, "ShareFiles", "StoredRelativePath", cancellationToken);
            if (!hasShareFileStoredRelativePath)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "ShareFiles" ADD COLUMN "StoredRelativePath" TEXT NULL""",
                    cancellationToken);
            }
    
            var hasShareFileRenderType = await SqliteColumnExistsAsync(db, "ShareFiles", "RenderType", cancellationToken);
            if (!hasShareFileRenderType)
            {
                await db.Database.ExecuteSqlRawAsync(
                    """ALTER TABLE "ShareFiles" ADD COLUMN "RenderType" TEXT NOT NULL DEFAULT 'binary'""",
                    cancellationToken);
            }
        }
        else if (db.Database.IsSqlServer())
        {
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'DefaultNotifyMode') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [DefaultNotifyMode] nvarchar(20) NOT NULL CONSTRAINT [DF_Users_DefaultNotifyMode] DEFAULT 'once'
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'DefaultExpiryMode') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [DefaultExpiryMode] nvarchar(20) NOT NULL CONSTRAINT [DF_Users_DefaultExpiryMode] DEFAULT '7_days'
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'FailedLoginCount') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [FailedLoginCount] int NOT NULL CONSTRAINT [DF_Users_FailedLoginCount] DEFAULT 0
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'LastFailedLoginAtUtc') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [LastFailedLoginAtUtc] datetime2 NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'LockoutEndUtc') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [LockoutEndUtc] datetime2 NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'EmailConfirmed') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [EmailConfirmed] bit NOT NULL CONSTRAINT [DF_Users_EmailConfirmed] DEFAULT 1
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'EmailConfirmedAtUtc') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [EmailConfirmedAtUtc] datetime2 NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'EmailConfirmationTokenHash') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [EmailConfirmationTokenHash] nvarchar(64) NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'EmailConfirmationTokenExpiresAtUtc') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [EmailConfirmationTokenExpiresAtUtc] datetime2 NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'PendingEmail') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [PendingEmail] nvarchar(320) NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'PendingEmailTokenHash') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [PendingEmailTokenHash] nvarchar(64) NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'PendingEmailTokenExpiresAtUtc') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [PendingEmailTokenExpiresAtUtc] datetime2 NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'PendingPasswordHash') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [PendingPasswordHash] nvarchar(1000) NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'PendingPasswordTokenHash') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [PendingPasswordTokenHash] nvarchar(64) NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'PendingPasswordTokenExpiresAtUtc') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [PendingPasswordTokenExpiresAtUtc] datetime2 NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'PasswordResetTokenHash') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [PasswordResetTokenHash] nvarchar(64) NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Users', 'PasswordResetTokenExpiresAtUtc') IS NULL
                BEGIN
                  ALTER TABLE [Users] ADD [PasswordResetTokenExpiresAtUtc] datetime2 NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('AccountTemplates', 'BackgroundColorHex') IS NULL
                BEGIN
                  ALTER TABLE [AccountTemplates] ADD [BackgroundColorHex] nvarchar(16) NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('AccountTemplates', 'ContainerPosition') IS NULL
                BEGIN
                  ALTER TABLE [AccountTemplates] ADD [ContainerPosition] nvarchar(32) NOT NULL CONSTRAINT [DF_AccountTemplates_ContainerPosition] DEFAULT 'center'
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Shares', 'PageBackgroundColorHex') IS NULL
                BEGIN
                  ALTER TABLE [Shares] ADD [PageBackgroundColorHex] nvarchar(16) NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Shares', 'PageContainerPosition') IS NULL
                BEGIN
                  ALTER TABLE [Shares] ADD [PageContainerPosition] nvarchar(32) NOT NULL CONSTRAINT [DF_Shares_PageContainerPosition] DEFAULT 'center'
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Shares', 'ShareToken') IS NULL
                BEGIN
                  ALTER TABLE [Shares] ADD [ShareToken] nvarchar(120) NOT NULL CONSTRAINT [DF_Shares_ShareToken] DEFAULT ''
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Shares', 'DownloadPasswordHash') IS NULL
                BEGIN
                  ALTER TABLE [Shares] ADD [DownloadPasswordHash] nvarchar(1000) NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Shares', 'ShareExperienceType') IS NULL
                BEGIN
                  ALTER TABLE [Shares] ADD [ShareExperienceType] nvarchar(32) NOT NULL CONSTRAINT [DF_Shares_ShareExperienceType] DEFAULT 'archive'
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Shares', 'AccessMode') IS NULL
                BEGIN
                  ALTER TABLE [Shares] ADD [AccessMode] nvarchar(32) NOT NULL CONSTRAINT [DF_Shares_AccessMode] DEFAULT 'download_only'
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('Shares', 'ContentRootPath') IS NULL
                BEGIN
                  ALTER TABLE [Shares] ADD [ContentRootPath] nvarchar(400) NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('ShareFiles', 'StoredRelativePath') IS NULL
                BEGIN
                  ALTER TABLE [ShareFiles] ADD [StoredRelativePath] nvarchar(400) NULL
                END
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                IF COL_LENGTH('ShareFiles', 'RenderType') IS NULL
                BEGIN
                  ALTER TABLE [ShareFiles] ADD [RenderType] nvarchar(32) NOT NULL CONSTRAINT [DF_ShareFiles_RenderType] DEFAULT 'binary'
                END
                """,
                cancellationToken);
        }
    }
    
    private static async Task<bool> SqliteColumnExistsAsync(AgoraDbContext db, string tableName, string columnName, CancellationToken cancellationToken)
    {
        var connection = db.Database.GetDbConnection();
        var openedHere = false;
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync(cancellationToken);
            openedHere = true;
        }
    
        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT COUNT(*) FROM pragma_table_info('{tableName}') WHERE name = @columnName";
            var parameter = command.CreateParameter();
            parameter.ParameterName = "@columnName";
            parameter.Value = columnName;
            command.Parameters.Add(parameter);
            var result = await command.ExecuteScalarAsync(cancellationToken);
            return Convert.ToInt32(result) > 0;
        }
        finally
        {
            if (openedHere)
            {
                await connection.CloseAsync();
            }
        }
    }
    
}
