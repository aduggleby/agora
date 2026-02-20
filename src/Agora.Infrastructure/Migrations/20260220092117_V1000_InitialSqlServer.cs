using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Agora.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class V1000_InitialSqlServer : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AccountTemplates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UploaderEmail = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    Title = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    H1 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    BackgroundImageUrl = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    BackgroundColorHex = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: true),
                    ContainerPosition = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccountTemplates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Shares",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UploaderEmail = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    ShareToken = table.Column<string>(type: "nvarchar(120)", maxLength: 120, nullable: false),
                    ZipDisplayName = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    ZipDiskPath = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ZipSizeBytes = table.Column<long>(type: "bigint", nullable: false),
                    ShareExperienceType = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    AccessMode = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    ContentRootPath = table.Column<string>(type: "nvarchar(400)", maxLength: 400, nullable: true),
                    DownloadPasswordHash = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                    UploaderMessage = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    SenderName = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    SenderEmail = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: true),
                    SenderMessage = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    NotifyMode = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    FirstDownloadedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    DeletedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PageTitle = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PageH1 = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PageDescription = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    BackgroundImageUrl = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    PageBackgroundColorHex = table.Column<string>(type: "nvarchar(16)", maxLength: 16, nullable: true),
                    PageContainerPosition = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Shares", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SystemSettings",
                columns: table => new
                {
                    Key = table.Column<string>(type: "nvarchar(120)", maxLength: 120, nullable: false),
                    Value = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: false),
                    UpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SystemSettings", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Email = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    DisplayName = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    EmailConfirmed = table.Column<bool>(type: "bit", nullable: false),
                    EmailConfirmedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    EmailConfirmationTokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    EmailConfirmationTokenExpiresAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PendingEmail = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: true),
                    PendingEmailTokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    PendingEmailTokenExpiresAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PasswordHash = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: false),
                    PendingPasswordHash = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                    PendingPasswordTokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    PendingPasswordTokenExpiresAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    PasswordResetTokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    PasswordResetTokenExpiresAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Role = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false),
                    DefaultNotifyMode = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false),
                    DefaultExpiryMode = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    UploadToken = table.Column<string>(type: "nvarchar(120)", maxLength: 120, nullable: false),
                    UploadTokenUpdatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    FailedLoginCount = table.Column<int>(type: "int", nullable: false, defaultValue: 0),
                    LastFailedLoginAtUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    LockoutEndUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DownloadEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ShareId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    IpAddress = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    UserAgent = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    BrowserMetadataJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    DownloadedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    NotificationSent = table.Column<bool>(type: "bit", nullable: false),
                    NotificationError = table.Column<string>(type: "nvarchar(max)", nullable: true)
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
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ShareId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    OriginalFilename = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    StoredRelativePath = table.Column<string>(type: "nvarchar(400)", maxLength: 400, nullable: true),
                    RenderType = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    OriginalSizeBytes = table.Column<long>(type: "bigint", nullable: false),
                    DetectedContentType = table.Column<string>(type: "nvarchar(150)", maxLength: 150, nullable: false)
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
                name: "IX_Shares_ShareToken",
                table: "Shares",
                column: "ShareToken",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_UploadToken",
                table: "Users",
                column: "UploadToken",
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
