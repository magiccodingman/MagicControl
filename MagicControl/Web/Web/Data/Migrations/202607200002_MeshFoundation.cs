using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MagicControl.Web.Data.Migrations;

public partial class MeshFoundation : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<long>(
            name: "ManifestRevision",
            table: "Groups",
            nullable: false,
            defaultValue: 1L);

        migrationBuilder.AddColumn<long>(
            name: "OfflineTrustDurationSeconds",
            table: "Groups",
            nullable: true);

        migrationBuilder.AddColumn<Guid>(
            name: "SecurityEpoch",
            table: "Groups",
            nullable: false,
            defaultValue: Guid.Empty);

        migrationBuilder.AddColumn<string>(
            name: "SecurityMode",
            table: "Groups",
            maxLength: 32,
            nullable: false,
            defaultValue: "Open");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(name: "ManifestRevision", table: "Groups");
        migrationBuilder.DropColumn(name: "OfflineTrustDurationSeconds", table: "Groups");
        migrationBuilder.DropColumn(name: "SecurityEpoch", table: "Groups");
        migrationBuilder.DropColumn(name: "SecurityMode", table: "Groups");
    }
}
