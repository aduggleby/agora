using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Agora.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddOwnerUserId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "OwnerUserId",
                table: "Shares",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "OwnerUserId",
                table: "AccountTemplates",
                type: "uniqueidentifier",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Shares_OwnerUserId",
                table: "Shares",
                column: "OwnerUserId");

            migrationBuilder.CreateIndex(
                name: "IX_AccountTemplates_OwnerUserId",
                table: "AccountTemplates",
                column: "OwnerUserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Shares_OwnerUserId",
                table: "Shares");

            migrationBuilder.DropIndex(
                name: "IX_AccountTemplates_OwnerUserId",
                table: "AccountTemplates");

            migrationBuilder.DropColumn(
                name: "OwnerUserId",
                table: "Shares");

            migrationBuilder.DropColumn(
                name: "OwnerUserId",
                table: "AccountTemplates");
        }
    }
}
