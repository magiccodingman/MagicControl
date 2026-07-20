using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MagicControl.Web.Data.Migrations;

[DbContext(typeof(MagicControlDbContext))]
[Migration("202607200003_ConnectedMagicSettings")]
public partial class ConnectedMagicSettings : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "BootstrapNonce",
            table: "EnrollmentRequests",
            maxLength: 128,
            nullable: false,
            defaultValue: "");

        migrationBuilder.AddColumn<string>(
            name: "PairingCode",
            table: "EnrollmentRequests",
            maxLength: 32,
            nullable: false,
            defaultValue: "");

        migrationBuilder.AddColumn<Guid>(
            name: "GroupId",
            table: "EnrollmentRequests",
            nullable: true);

        migrationBuilder.AddColumn<string>(
            name: "EndpointsJson",
            table: "EnrollmentRequests",
            nullable: false,
            defaultValue: "[]");

        migrationBuilder.AddColumn<string>(
            name: "SchemaManifestJson",
            table: "EnrollmentRequests",
            nullable: false,
            defaultValue: "{}");

        migrationBuilder.AddColumn<string>(
            name: "MigrationReportJson",
            table: "EnrollmentRequests",
            nullable: false,
            defaultValue: "null");

        migrationBuilder.AddColumn<string>(
            name: "EndpointsJson",
            table: "ManagedInstances",
            nullable: false,
            defaultValue: "[]");

        migrationBuilder.AddColumn<long>(
            name: "DirectorySequence",
            table: "ManagedInstances",
            nullable: false,
            defaultValue: 0L);

        migrationBuilder.CreateTable(
            name: "ApplicationSchemas",
            columns: table => new
            {
                Id = table.Column<Guid>(nullable: false),
                GroupId = table.Column<Guid>(nullable: false),
                ApplicationName = table.Column<string>(maxLength: 200, nullable: false),
                ApplicationVersion = table.Column<string>(maxLength: 128, nullable: false),
                SchemaVersion = table.Column<int>(nullable: false),
                SchemaFingerprint = table.Column<string>(maxLength: 128, nullable: false),
                ManifestJson = table.Column<string>(nullable: false),
                MigrationReviewJson = table.Column<string>(nullable: false),
                SettingsRevision = table.Column<long>(nullable: false),
                CreatedUtc = table.Column<DateTimeOffset>(nullable: false),
                UpdatedUtc = table.Column<DateTimeOffset>(nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ApplicationSchemas", x => x.Id);
                table.ForeignKey(
                    name: "FK_ApplicationSchemas_Groups_GroupId",
                    column: x => x.GroupId,
                    principalTable: "Groups",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "ApplicationSettingOverrides",
            columns: table => new
            {
                Id = table.Column<Guid>(nullable: false),
                ApplicationSchemaId = table.Column<Guid>(nullable: false),
                Path = table.Column<string>(maxLength: 512, nullable: false),
                ScopeKind = table.Column<string>(maxLength: 32, nullable: false),
                ScopeValue = table.Column<string>(maxLength: 256, nullable: false),
                ValueState = table.Column<string>(maxLength: 32, nullable: false),
                ValueJson = table.Column<string>(nullable: true),
                Durability = table.Column<string>(maxLength: 32, nullable: false),
                PersistOffline = table.Column<bool>(nullable: false),
                IsSecret = table.Column<bool>(nullable: false),
                ProtectedSecret = table.Column<string>(nullable: true),
                ExpiresUtc = table.Column<DateTimeOffset>(nullable: true),
                Revision = table.Column<long>(nullable: false),
                UpdatedByUserId = table.Column<Guid>(nullable: false),
                UpdatedUtc = table.Column<DateTimeOffset>(nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ApplicationSettingOverrides", x => x.Id);
                table.ForeignKey(
                    name: "FK_ApplicationSettingOverrides_ApplicationSchemas_ApplicationSchemaId",
                    column: x => x.ApplicationSchemaId,
                    principalTable: "ApplicationSchemas",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_EnrollmentRequests_GroupId",
            table: "EnrollmentRequests",
            column: "GroupId");

        migrationBuilder.CreateIndex(
            name: "IX_ApplicationSchemas_GroupId_ApplicationName",
            table: "ApplicationSchemas",
            columns: new[] { "GroupId", "ApplicationName" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_ApplicationSettingOverrides_ApplicationSchemaId_Path_ScopeKind_ScopeValue",
            table: "ApplicationSettingOverrides",
            columns: new[] { "ApplicationSchemaId", "Path", "ScopeKind", "ScopeValue" },
            unique: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "ApplicationSettingOverrides");
        migrationBuilder.DropTable(name: "ApplicationSchemas");
        migrationBuilder.DropIndex(name: "IX_EnrollmentRequests_GroupId", table: "EnrollmentRequests");

        migrationBuilder.DropColumn(name: "BootstrapNonce", table: "EnrollmentRequests");
        migrationBuilder.DropColumn(name: "PairingCode", table: "EnrollmentRequests");
        migrationBuilder.DropColumn(name: "GroupId", table: "EnrollmentRequests");
        migrationBuilder.DropColumn(name: "EndpointsJson", table: "EnrollmentRequests");
        migrationBuilder.DropColumn(name: "SchemaManifestJson", table: "EnrollmentRequests");
        migrationBuilder.DropColumn(name: "MigrationReportJson", table: "EnrollmentRequests");
        migrationBuilder.DropColumn(name: "EndpointsJson", table: "ManagedInstances");
        migrationBuilder.DropColumn(name: "DirectorySequence", table: "ManagedInstances");
    }
}
