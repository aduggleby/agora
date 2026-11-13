using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Agora.Infrastructure.Migrations.Postgres
{
    /// <inheritdoc />
    public partial class AddShareTokenReservations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ShareTokenReservations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Token = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    OwnerUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    DraftShareId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ShareTokenReservations", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ShareTokenReservations_CreatedAtUtc",
                table: "ShareTokenReservations",
                column: "CreatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ShareTokenReservations_Token",
                table: "ShareTokenReservations",
                column: "Token",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ShareTokenReservations");
        }
    }
}
