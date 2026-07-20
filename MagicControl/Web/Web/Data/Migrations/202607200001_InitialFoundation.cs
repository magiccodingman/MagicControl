using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MagicControl.Web.Data.Migrations;

public partial class InitialFoundation : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "AuditEvents",
            columns: table => new
            {
                Id = table.Column<Guid>(nullable: false),
                OccurredUtc = table.Column<DateTimeOffset>(nullable: false),
                ActorType = table.Column<string>(maxLength: 64, nullable: true),
                ActorId = table.Column<string>(maxLength: 200, nullable: true),
                Action = table.Column<string>(maxLength: 200, nullable: false),
                TargetType = table.Column<string>(maxLength: 200, nullable: false),
                TargetId = table.Column<string>(maxLength: 200, nullable: true),
                MetadataJson = table.Column<string>(nullable: false)
            },
            constraints: table => table.PrimaryKey("PK_AuditEvents", x => x.Id));

        migrationBuilder.CreateTable(
            name: "Groups",
            columns: table => new
            {
                Id = table.Column<Guid>(nullable: false),
                Name = table.Column<string>(maxLength: 160, nullable: false),
                NormalizedName = table.Column<string>(maxLength: 160, nullable: false),
                Description = table.Column<string>(maxLength: 2000, nullable: true),
                AllowOpenLocalMembers = table.Column<bool>(nullable: false),
                CreatedUtc = table.Column<DateTimeOffset>(nullable: false),
                UpdatedUtc = table.Column<DateTimeOffset>(nullable: false)
            },
            constraints: table => table.PrimaryKey("PK_Groups", x => x.Id));

        migrationBuilder.CreateTable(
            name: "Roles",
            columns: table => new
            {
                Id = table.Column<Guid>(nullable: false),
                Name = table.Column<string>(maxLength: 128, nullable: false),
                NormalizedName = table.Column<string>(maxLength: 128, nullable: false),
                IsBuiltIn = table.Column<bool>(nullable: false),
                CreatedUtc = table.Column<DateTimeOffset>(nullable: false)
            },
            constraints: table => table.PrimaryKey("PK_Roles", x => x.Id));

        migrationBuilder.CreateTable(
            name: "SystemState",
            columns: table => new
            {
                Key = table.Column<string>(maxLength: 128, nullable: false),
                Value = table.Column<string>(maxLength: 2048, nullable: false),
                UpdatedUtc = table.Column<DateTimeOffset>(nullable: false)
            },
            constraints: table => table.PrimaryKey("PK_SystemState", x => x.Key));

        migrationBuilder.CreateTable(
            name: "UsedProofNonces",
            columns: table => new
            {
                CredentialId = table.Column<Guid>(nullable: false),
                Nonce = table.Column<string>(maxLength: 256, nullable: false),
                ExpiresUtc = table.Column<DateTimeOffset>(nullable: false),
                UsedUtc = table.Column<DateTimeOffset>(nullable: false)
            },
            constraints: table => table.PrimaryKey("PK_UsedProofNonces", x => new { x.CredentialId, x.Nonce }));

        migrationBuilder.CreateTable(
            name: "Users",
            columns: table => new
            {
                Id = table.Column<Guid>(nullable: false),
                Username = table.Column<string>(maxLength: 128, nullable: false),
                NormalizedUsername = table.Column<string>(maxLength: 128, nullable: false),
                PasswordHash = table.Column<string>(maxLength: 2048, nullable: false),
                SecurityStamp = table.Column<string>(maxLength: 128, nullable: false),
                MustChangePassword = table.Column<bool>(nullable: false),
                IsDisabled = table.Column<bool>(nullable: false),
                FailedLoginCount = table.Column<int>(nullable: false),
                LockoutEndUtc = table.Column<DateTimeOffset>(nullable: true),
                CreatedUtc = table.Column<DateTimeOffset>(nullable: false),
                UpdatedUtc = table.Column<DateTimeOffset>(nullable: false),
                PasswordChangedUtc = table.Column<DateTimeOffset>(nullable: false),
                LastLoginUtc = table.Column<DateTimeOffset>(nullable: true)
            },
            constraints: table => table.PrimaryKey("PK_Users", x => x.Id));

        migrationBuilder.CreateTable(
            name: "ManagedInstances",
            columns: table => new
            {
                Id = table.Column<Guid>(nullable: false),
                Kind = table.Column<string>(maxLength: 64, nullable: false),
                Status = table.Column<string>(maxLength: 64, nullable: false),
                DisplayName = table.Column<string>(maxLength: 200, nullable: false),
                ApplicationName = table.Column<string>(maxLength: 200, nullable: true),
                InstanceName = table.Column<string>(maxLength: 200, nullable: true),
                InstanceRole = table.Column<string>(maxLength: 200, nullable: true),
                SiteName = table.Column<string>(maxLength: 200, nullable: true),
                AdvertisedEndpoint = table.Column<string>(maxLength: 2048, nullable: true),
                Version = table.Column<string>(maxLength: 128, nullable: true),
                CapabilitiesJson = table.Column<string>(nullable: false),
                MetadataJson = table.Column<string>(nullable: false),
                GroupId = table.Column<Guid>(nullable: true),
                CreatedUtc = table.Column<DateTimeOffset>(nullable: false),
                ApprovedUtc = table.Column<DateTimeOffset>(nullable: false),
                LastSeenUtc = table.Column<DateTimeOffset>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_ManagedInstances", x => x.Id);
                table.ForeignKey(
                    name: "FK_ManagedInstances_Groups_GroupId",
                    column: x => x.GroupId,
                    principalTable: "Groups",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.SetNull);
            });

        migrationBuilder.CreateTable(
            name: "UserRoles",
            columns: table => new
            {
                UserId = table.Column<Guid>(nullable: false),
                RoleId = table.Column<Guid>(nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_UserRoles", x => new { x.UserId, x.RoleId });
                table.ForeignKey(
                    name: "FK_UserRoles_Roles_RoleId",
                    column: x => x.RoleId,
                    principalTable: "Roles",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_UserRoles_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "EnrollmentRequests",
            columns: table => new
            {
                Id = table.Column<Guid>(nullable: false),
                Kind = table.Column<string>(maxLength: 64, nullable: false),
                Status = table.Column<string>(maxLength: 64, nullable: false),
                NodeId = table.Column<Guid>(nullable: false),
                CredentialId = table.Column<Guid>(nullable: false),
                PublicKey = table.Column<string>(maxLength: 4096, nullable: false),
                Fingerprint = table.Column<string>(maxLength: 128, nullable: false),
                SignatureAlgorithm = table.Column<string>(maxLength: 128, nullable: false),
                DisplayName = table.Column<string>(maxLength: 200, nullable: false),
                ApplicationName = table.Column<string>(maxLength: 200, nullable: true),
                GroupName = table.Column<string>(maxLength: 200, nullable: true),
                InstanceName = table.Column<string>(maxLength: 200, nullable: true),
                InstanceRole = table.Column<string>(maxLength: 200, nullable: true),
                SiteName = table.Column<string>(maxLength: 200, nullable: true),
                Version = table.Column<string>(maxLength: 128, nullable: true),
                AdvertisedEndpoint = table.Column<string>(maxLength: 2048, nullable: true),
                RequestedRolesJson = table.Column<string>(nullable: false),
                CapabilitiesJson = table.Column<string>(nullable: false),
                MetadataJson = table.Column<string>(nullable: false),
                FirstSeenUtc = table.Column<DateTimeOffset>(nullable: false),
                LastSeenUtc = table.Column<DateTimeOffset>(nullable: false),
                ReviewedUtc = table.Column<DateTimeOffset>(nullable: true),
                ReviewedByUserId = table.Column<Guid>(nullable: true),
                DecisionReason = table.Column<string>(maxLength: 2000, nullable: true),
                ManagedInstanceId = table.Column<Guid>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_EnrollmentRequests", x => x.Id);
                table.ForeignKey(
                    name: "FK_EnrollmentRequests_ManagedInstances_ManagedInstanceId",
                    column: x => x.ManagedInstanceId,
                    principalTable: "ManagedInstances",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.SetNull);
            });

        migrationBuilder.CreateTable(
            name: "InstanceCredentials",
            columns: table => new
            {
                Id = table.Column<Guid>(nullable: false),
                NodeId = table.Column<Guid>(nullable: false),
                CredentialId = table.Column<Guid>(nullable: false),
                PublicKey = table.Column<string>(maxLength: 4096, nullable: false),
                Fingerprint = table.Column<string>(maxLength: 128, nullable: false),
                SignatureAlgorithm = table.Column<string>(maxLength: 128, nullable: false),
                Status = table.Column<string>(maxLength: 64, nullable: false),
                ManagedInstanceId = table.Column<Guid>(nullable: true),
                CreatedUtc = table.Column<DateTimeOffset>(nullable: false),
                UpdatedUtc = table.Column<DateTimeOffset>(nullable: false),
                RetiringUtc = table.Column<DateTimeOffset>(nullable: true),
                RevokedUtc = table.Column<DateTimeOffset>(nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_InstanceCredentials", x => x.Id);
                table.ForeignKey(
                    name: "FK_InstanceCredentials_ManagedInstances_ManagedInstanceId",
                    column: x => x.ManagedInstanceId,
                    principalTable: "ManagedInstances",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.SetNull);
            });

        migrationBuilder.CreateIndex(
            name: "IX_AuditEvents_OccurredUtc",
            table: "AuditEvents",
            column: "OccurredUtc");

        migrationBuilder.CreateIndex(
            name: "IX_EnrollmentRequests_ManagedInstanceId",
            table: "EnrollmentRequests",
            column: "ManagedInstanceId");

        migrationBuilder.CreateIndex(
            name: "IX_EnrollmentRequests_NodeId_CredentialId_Kind",
            table: "EnrollmentRequests",
            columns: new[] { "NodeId", "CredentialId", "Kind" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_EnrollmentRequests_Status_Kind_LastSeenUtc",
            table: "EnrollmentRequests",
            columns: new[] { "Status", "Kind", "LastSeenUtc" });

        migrationBuilder.CreateIndex(
            name: "IX_Groups_NormalizedName",
            table: "Groups",
            column: "NormalizedName",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_InstanceCredentials_Fingerprint",
            table: "InstanceCredentials",
            column: "Fingerprint");

        migrationBuilder.CreateIndex(
            name: "IX_InstanceCredentials_ManagedInstanceId",
            table: "InstanceCredentials",
            column: "ManagedInstanceId");

        migrationBuilder.CreateIndex(
            name: "IX_InstanceCredentials_NodeId_CredentialId",
            table: "InstanceCredentials",
            columns: new[] { "NodeId", "CredentialId" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_ManagedInstances_ApplicationName_InstanceName",
            table: "ManagedInstances",
            columns: new[] { "ApplicationName", "InstanceName" });

        migrationBuilder.CreateIndex(
            name: "IX_ManagedInstances_GroupId",
            table: "ManagedInstances",
            column: "GroupId");

        migrationBuilder.CreateIndex(
            name: "IX_ManagedInstances_SiteName",
            table: "ManagedInstances",
            column: "SiteName");

        migrationBuilder.CreateIndex(
            name: "IX_Roles_NormalizedName",
            table: "Roles",
            column: "NormalizedName",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_UsedProofNonces_ExpiresUtc",
            table: "UsedProofNonces",
            column: "ExpiresUtc");

        migrationBuilder.CreateIndex(
            name: "IX_UserRoles_RoleId",
            table: "UserRoles",
            column: "RoleId");

        migrationBuilder.CreateIndex(
            name: "IX_Users_NormalizedUsername",
            table: "Users",
            column: "NormalizedUsername",
            unique: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "AuditEvents");
        migrationBuilder.DropTable(name: "EnrollmentRequests");
        migrationBuilder.DropTable(name: "InstanceCredentials");
        migrationBuilder.DropTable(name: "SystemState");
        migrationBuilder.DropTable(name: "UsedProofNonces");
        migrationBuilder.DropTable(name: "UserRoles");
        migrationBuilder.DropTable(name: "ManagedInstances");
        migrationBuilder.DropTable(name: "Roles");
        migrationBuilder.DropTable(name: "Users");
        migrationBuilder.DropTable(name: "Groups");
    }
}
