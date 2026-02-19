using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Agora.Infrastructure.Persistence.Migrations
{
    public partial class V0901_ShareTokenPlaintextOnly : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Shares_ShareTokenHash",
                table: "Shares");

            migrationBuilder.DropColumn(
                name: "ShareTokenHash",
                table: "Shares");

            migrationBuilder.DropColumn(
                name: "ShareTokenPrefix",
                table: "Shares");

            if (ActiveProvider.Contains("Sqlite", StringComparison.OrdinalIgnoreCase))
            {
                migrationBuilder.Sql(
                    """
                    UPDATE "Shares"
                    SET "ShareToken" = lower(hex(randomblob(16)))
                    WHERE trim(coalesce("ShareToken", '')) = '';
                    """);
            }
            else if (ActiveProvider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
            {
                migrationBuilder.Sql(
                    """
                    UPDATE [Shares]
                    SET [ShareToken] = REPLACE(CONVERT(nvarchar(36), NEWID()), '-', '')
                    WHERE LTRIM(RTRIM(ISNULL([ShareToken], ''))) = '';
                    """);
            }

            migrationBuilder.CreateIndex(
                name: "IX_Shares_ShareToken",
                table: "Shares",
                column: "ShareToken",
                unique: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new NotSupportedException("Down migration is not supported for V0901_ShareTokenPlaintextOnly.");
        }
    }
}
