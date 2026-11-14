using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Agora.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddAgentAccess : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AllowAgentUploads",
                table: "Users",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<Guid>(
                name: "CreatedByApiTokenId",
                table: "Shares",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "SentByAgent",
                table: "Shares",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "AccessLevel",
                table: "ApiTokens",
                type: "nvarchar(16)",
                maxLength: 16,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Shares_CreatedByApiTokenId",
                table: "Shares",
                column: "CreatedByApiTokenId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Shares_CreatedByApiTokenId",
                table: "Shares");

            migrationBuilder.DropColumn(
                name: "AllowAgentUploads",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "CreatedByApiTokenId",
                table: "Shares");

            migrationBuilder.DropColumn(
                name: "SentByAgent",
                table: "Shares");

            migrationBuilder.DropColumn(
                name: "AccessLevel",
                table: "ApiTokens");
        }
    }
}
