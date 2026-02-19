using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Agora.Infrastructure.Persistence.Migrations
{
    public partial class V0902_PublicUploadLinksAndSenderMetadata : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SenderName",
                table: "Shares",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SenderEmail",
                table: "Shares",
                maxLength: 320,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SenderMessage",
                table: "Shares",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "UploadToken",
                table: "Users",
                maxLength: 120,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "UploadTokenUpdatedAtUtc",
                table: "Users",
                nullable: true);

            if (ActiveProvider.Contains("Sqlite", StringComparison.OrdinalIgnoreCase))
            {
                migrationBuilder.Sql(
                    """
                    UPDATE "Users"
                    SET "UploadToken" = lower(hex(randomblob(16))),
                        "UploadTokenUpdatedAtUtc" = CURRENT_TIMESTAMP
                    WHERE trim(coalesce("UploadToken", '')) = '';
                    """);
            }
            else if (ActiveProvider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
            {
                migrationBuilder.Sql(
                    """
                    UPDATE [Users]
                    SET [UploadToken] = REPLACE(CONVERT(nvarchar(36), NEWID()), '-', ''),
                        [UploadTokenUpdatedAtUtc] = SYSUTCDATETIME()
                    WHERE LTRIM(RTRIM(ISNULL([UploadToken], ''))) = '';
                    """);
            }

            migrationBuilder.CreateIndex(
                name: "IX_Users_UploadToken",
                table: "Users",
                column: "UploadToken",
                unique: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new NotSupportedException("Down migration is not supported for V0902_PublicUploadLinksAndSenderMetadata.");
        }
    }
}
