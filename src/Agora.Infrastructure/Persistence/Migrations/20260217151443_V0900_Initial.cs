using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Agora.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class V0900_Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AccountTemplates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UploaderEmail = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                    Title = table.Column<string>(type: "TEXT", nullable: false),
                    H1 = table.Column<string>(type: "TEXT", nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: false),
                    BackgroundImageUrl = table.Column<string>(type: "TEXT", nullable: true),
                    BackgroundColorHex = table.Column<string>(type: "TEXT", maxLength: 16, nullable: true),
                    ContainerPosition = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccountTemplates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Shares",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UploaderEmail = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                    ShareToken = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    ShareTokenHash = table.Column<string>(type: "TEXT", nullable: false),
                    ShareTokenPrefix = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    ZipDisplayName = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    ZipDiskPath = table.Column<string>(type: "TEXT", nullable: false),
                    ZipSizeBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    ShareExperienceType = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    AccessMode = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    ContentRootPath = table.Column<string>(type: "TEXT", maxLength: 400, nullable: true),
                    DownloadPasswordHash = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    UploaderMessage = table.Column<string>(type: "TEXT", nullable: true),
                    NotifyMode = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    FirstDownloadedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DeletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    PageTitle = table.Column<string>(type: "TEXT", nullable: false),
                    PageH1 = table.Column<string>(type: "TEXT", nullable: false),
                    PageDescription = table.Column<string>(type: "TEXT", nullable: false),
                    BackgroundImageUrl = table.Column<string>(type: "TEXT", nullable: true),
                    PageBackgroundColorHex = table.Column<string>(type: "TEXT", maxLength: 16, nullable: true),
                    PageContainerPosition = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Shares", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SystemSettings",
                columns: table => new
                {
                    Key = table.Column<string>(type: "TEXT", maxLength: 120, nullable: false),
                    Value = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SystemSettings", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Email = table.Column<string>(type: "TEXT", maxLength: 320, nullable: false),
                    EmailConfirmed = table.Column<bool>(type: "INTEGER", nullable: false),
                    EmailConfirmedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    EmailConfirmationTokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    EmailConfirmationTokenExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    PendingEmail = table.Column<string>(type: "TEXT", maxLength: 320, nullable: true),
                    PendingEmailTokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    PendingEmailTokenExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    PasswordHash = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    PendingPasswordHash = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    PendingPasswordTokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    PendingPasswordTokenExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    PasswordResetTokenHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    PasswordResetTokenExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Role = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    DefaultNotifyMode = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    DefaultExpiryMode = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    FailedLoginCount = table.Column<int>(type: "INTEGER", nullable: false, defaultValue: 0),
                    LastFailedLoginAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LockoutEndUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DownloadEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ShareId = table.Column<Guid>(type: "TEXT", nullable: false),
                    IpAddress = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    UserAgent = table.Column<string>(type: "TEXT", nullable: false),
                    BrowserMetadataJson = table.Column<string>(type: "TEXT", nullable: false),
                    DownloadedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    NotificationSent = table.Column<bool>(type: "INTEGER", nullable: false),
                    NotificationError = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DownloadEvents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DownloadEvents_Shares_ShareId",
                        column: x => x.ShareId,
                        principalTable: "Shares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ShareFiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ShareId = table.Column<Guid>(type: "TEXT", nullable: false),
                    OriginalFilename = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    StoredRelativePath = table.Column<string>(type: "TEXT", maxLength: 400, nullable: true),
                    RenderType = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    OriginalSizeBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    DetectedContentType = table.Column<string>(type: "TEXT", maxLength: 150, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ShareFiles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ShareFiles_Shares_ShareId",
                        column: x => x.ShareId,
                        principalTable: "Shares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AccountTemplates_UploaderEmail",
                table: "AccountTemplates",
                column: "UploaderEmail",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DownloadEvents_ShareId",
                table: "DownloadEvents",
                column: "ShareId");

            migrationBuilder.CreateIndex(
                name: "IX_ShareFiles_ShareId",
                table: "ShareFiles",
                column: "ShareId");

            migrationBuilder.CreateIndex(
                name: "IX_Shares_ShareTokenHash",
                table: "Shares",
                column: "ShareTokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AccountTemplates");

            migrationBuilder.DropTable(
                name: "DownloadEvents");

            migrationBuilder.DropTable(
                name: "ShareFiles");

            migrationBuilder.DropTable(
                name: "SystemSettings");

            migrationBuilder.DropTable(
                name: "Users");

            migrationBuilder.DropTable(
                name: "Shares");
        }
    }
}
