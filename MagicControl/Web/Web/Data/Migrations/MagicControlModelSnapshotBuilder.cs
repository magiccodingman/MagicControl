using MagicControl.Shared.Enrollments;
using MagicControl.Shared.Mesh;
using MagicControl.Web.Data.Entities;
using MagicSettings.Share;
using Microsoft.EntityFrameworkCore;

#nullable disable

namespace MagicControl.Web.Data.Migrations;

internal static class MagicControlModelSnapshotBuilder
{
    public static void Build(ModelBuilder modelBuilder)
    {
        modelBuilder.HasAnnotation("ProductVersion", "10.0.0");

        modelBuilder.Entity<ControlUser>(b =>
        {
            b.Property<Guid>("Id");
            b.Property<DateTimeOffset>("CreatedUtc");
            b.Property<int>("FailedLoginCount");
            b.Property<bool>("IsDisabled");
            b.Property<DateTimeOffset?>("LastLoginUtc");
            b.Property<DateTimeOffset?>("LockoutEndUtc");
            b.Property<bool>("MustChangePassword");
            b.Property<string>("NormalizedUsername").IsRequired().HasMaxLength(128);
            b.Property<DateTimeOffset>("PasswordChangedUtc");
            b.Property<string>("PasswordHash").IsRequired().HasMaxLength(2048);
            b.Property<string>("SecurityStamp").IsRequired().HasMaxLength(128);
            b.Property<DateTimeOffset>("UpdatedUtc");
            b.Property<string>("Username").IsRequired().HasMaxLength(128);
            b.HasKey("Id");
            b.HasIndex("NormalizedUsername").IsUnique();
            b.ToTable("Users");
        });

        modelBuilder.Entity<ControlRole>(b =>
        {
            b.Property<Guid>("Id");
            b.Property<DateTimeOffset>("CreatedUtc");
            b.Property<bool>("IsBuiltIn");
            b.Property<string>("Name").IsRequired().HasMaxLength(128);
            b.Property<string>("NormalizedName").IsRequired().HasMaxLength(128);
            b.HasKey("Id");
            b.HasIndex("NormalizedName").IsUnique();
            b.ToTable("Roles");
        });

        modelBuilder.Entity<ControlUserRole>(b =>
        {
            b.Property<Guid>("UserId");
            b.Property<Guid>("RoleId");
            b.HasKey("UserId", "RoleId");
            b.HasIndex("RoleId");
            b.ToTable("UserRoles");
        });

        modelBuilder.Entity<SystemState>(b =>
        {
            b.Property<string>("Key").HasMaxLength(128);
            b.Property<DateTimeOffset>("UpdatedUtc");
            b.Property<string>("Value").IsRequired().HasMaxLength(2048);
            b.HasKey("Key");
            b.ToTable("SystemState");
        });

        modelBuilder.Entity<ControlGroup>(b =>
        {
            b.Property<Guid>("Id");
            b.Property<bool>("AllowOpenLocalMembers");
            b.Property<DateTimeOffset>("CreatedUtc");
            b.Property<string>("Description").HasMaxLength(2000);
            b.Property<long>("ManifestRevision");
            b.Property<string>("Name").IsRequired().HasMaxLength(160);
            b.Property<string>("NormalizedName").IsRequired().HasMaxLength(160);
            b.Property<long?>("OfflineTrustDurationSeconds");
            b.Property<Guid>("SecurityEpoch");
            b.Property<MagicControlGroupSecurityMode>("SecurityMode").HasConversion<string>().HasMaxLength(32);
            b.Property<DateTimeOffset>("UpdatedUtc");
            b.HasKey("Id");
            b.HasIndex("NormalizedName").IsUnique();
            b.ToTable("Groups");
        });

        modelBuilder.Entity<ManagedInstance>(b =>
        {
            b.Property<Guid>("Id");
            b.Property<string>("AdvertisedEndpoint").HasMaxLength(2048);
            b.Property<string>("ApplicationName").HasMaxLength(200);
            b.Property<DateTimeOffset>("ApprovedUtc");
            b.Property<string>("CapabilitiesJson").IsRequired();
            b.Property<DateTimeOffset>("CreatedUtc");
            b.Property<long>("DirectorySequence");
            b.Property<string>("DisplayName").IsRequired().HasMaxLength(200);
            b.Property<string>("EndpointsJson").IsRequired();
            b.Property<Guid?>("GroupId");
            b.Property<string>("InstanceName").HasMaxLength(200);
            b.Property<string>("InstanceRole").HasMaxLength(200);
            b.Property<EnrollmentKind>("Kind").HasConversion<string>().HasMaxLength(64);
            b.Property<DateTimeOffset?>("LastSeenUtc");
            b.Property<string>("MetadataJson").IsRequired();
            b.Property<string>("SiteName").HasMaxLength(200);
            b.Property<ManagedInstanceStatus>("Status").HasConversion<string>().HasMaxLength(64);
            b.Property<string>("Version").HasMaxLength(128);
            b.HasKey("Id");
            b.HasIndex("ApplicationName", "InstanceName");
            b.HasIndex("GroupId");
            b.HasIndex("SiteName");
            b.ToTable("ManagedInstances");
        });

        modelBuilder.Entity<InstanceCredential>(b =>
        {
            b.Property<Guid>("Id");
            b.Property<Guid>("CredentialId");
            b.Property<DateTimeOffset>("CreatedUtc");
            b.Property<string>("Fingerprint").IsRequired().HasMaxLength(128);
            b.Property<Guid?>("ManagedInstanceId");
            b.Property<Guid>("NodeId");
            b.Property<string>("PublicKey").IsRequired().HasMaxLength(4096);
            b.Property<DateTimeOffset?>("RetiringUtc");
            b.Property<DateTimeOffset?>("RevokedUtc");
            b.Property<string>("SignatureAlgorithm").IsRequired().HasMaxLength(128);
            b.Property<MagicCredentialStatus>("Status").HasConversion<string>().HasMaxLength(64);
            b.Property<DateTimeOffset>("UpdatedUtc");
            b.HasKey("Id");
            b.HasIndex("Fingerprint");
            b.HasIndex("ManagedInstanceId");
            b.HasIndex("NodeId", "CredentialId").IsUnique();
            b.ToTable("InstanceCredentials");
        });

        modelBuilder.Entity<EnrollmentRequestEntity>(b =>
        {
            b.Property<Guid>("Id");
            b.Property<string>("AdvertisedEndpoint").HasMaxLength(2048);
            b.Property<string>("ApplicationName").HasMaxLength(200);
            b.Property<string>("BootstrapNonce").IsRequired().HasMaxLength(128);
            b.Property<string>("CapabilitiesJson").IsRequired();
            b.Property<Guid>("CredentialId");
            b.Property<string>("DecisionReason").HasMaxLength(2000);
            b.Property<string>("DisplayName").IsRequired().HasMaxLength(200);
            b.Property<string>("EndpointsJson").IsRequired();
            b.Property<string>("Fingerprint").IsRequired().HasMaxLength(128);
            b.Property<DateTimeOffset>("FirstSeenUtc");
            b.Property<Guid?>("GroupId");
            b.Property<string>("GroupName").HasMaxLength(200);
            b.Property<string>("InstanceName").HasMaxLength(200);
            b.Property<string>("InstanceRole").HasMaxLength(200);
            b.Property<EnrollmentKind>("Kind").HasConversion<string>().HasMaxLength(64);
            b.Property<DateTimeOffset>("LastSeenUtc");
            b.Property<Guid?>("ManagedInstanceId");
            b.Property<string>("MetadataJson").IsRequired();
            b.Property<string>("MigrationReportJson").IsRequired();
            b.Property<Guid>("NodeId");
            b.Property<string>("PairingCode").IsRequired().HasMaxLength(32);
            b.Property<string>("PublicKey").IsRequired().HasMaxLength(4096);
            b.Property<string>("RequestedRolesJson").IsRequired();
            b.Property<Guid?>("ReviewedByUserId");
            b.Property<DateTimeOffset?>("ReviewedUtc");
            b.Property<string>("SchemaManifestJson").IsRequired();
            b.Property<string>("SignatureAlgorithm").IsRequired().HasMaxLength(128);
            b.Property<string>("SiteName").HasMaxLength(200);
            b.Property<EnrollmentRequestStatus>("Status").HasConversion<string>().HasMaxLength(64);
            b.Property<string>("Version").HasMaxLength(128);
            b.HasKey("Id");
            b.HasIndex("GroupId");
            b.HasIndex("ManagedInstanceId");
            b.HasIndex("NodeId", "CredentialId", "Kind").IsUnique();
            b.HasIndex("Status", "Kind", "LastSeenUtc");
            b.ToTable("EnrollmentRequests");
        });

        modelBuilder.Entity<ApplicationSchemaRecord>(b =>
        {
            b.Property<Guid>("Id");
            b.Property<string>("ApplicationName").IsRequired().HasMaxLength(200);
            b.Property<string>("ApplicationVersion").IsRequired().HasMaxLength(128);
            b.Property<DateTimeOffset>("CreatedUtc");
            b.Property<Guid>("GroupId");
            b.Property<string>("ManifestJson").IsRequired();
            b.Property<string>("MigrationReviewJson").IsRequired();
            b.Property<string>("SchemaFingerprint").IsRequired().HasMaxLength(128);
            b.Property<int>("SchemaVersion");
            b.Property<long>("SettingsRevision");
            b.Property<DateTimeOffset>("UpdatedUtc");
            b.HasKey("Id");
            b.HasIndex("GroupId", "ApplicationName").IsUnique();
            b.ToTable("ApplicationSchemas");
        });

        modelBuilder.Entity<ApplicationSettingOverride>(b =>
        {
            b.Property<Guid>("Id");
            b.Property<Guid>("ApplicationSchemaId");
            b.Property<MagicRemoteValueDurability>("Durability").HasConversion<string>().HasMaxLength(32);
            b.Property<DateTimeOffset?>("ExpiresUtc");
            b.Property<bool>("IsSecret");
            b.Property<string>("Path").IsRequired().HasMaxLength(512);
            b.Property<bool>("PersistOffline");
            b.Property<string>("ProtectedSecret");
            b.Property<long>("Revision");
            b.Property<MagicControlSettingScopeKind>("ScopeKind").HasConversion<string>().HasMaxLength(32);
            b.Property<string>("ScopeValue").IsRequired().HasMaxLength(256);
            b.Property<Guid>("UpdatedByUserId");
            b.Property<DateTimeOffset>("UpdatedUtc");
            b.Property<string>("ValueJson");
            b.Property<MagicValueState>("ValueState").HasConversion<string>().HasMaxLength(32);
            b.HasKey("Id");
            b.HasIndex("ApplicationSchemaId", "Path", "ScopeKind", "ScopeValue").IsUnique();
            b.ToTable("ApplicationSettingOverrides");
        });

        modelBuilder.Entity<UsedProofNonce>(b =>
        {
            b.Property<Guid>("CredentialId");
            b.Property<string>("Nonce").HasMaxLength(256);
            b.Property<DateTimeOffset>("ExpiresUtc");
            b.Property<DateTimeOffset>("UsedUtc");
            b.HasKey("CredentialId", "Nonce");
            b.HasIndex("ExpiresUtc");
            b.ToTable("UsedProofNonces");
        });

        modelBuilder.Entity<AuditEvent>(b =>
        {
            b.Property<Guid>("Id");
            b.Property<string>("Action").IsRequired().HasMaxLength(200);
            b.Property<string>("ActorId").HasMaxLength(200);
            b.Property<string>("ActorType").HasMaxLength(64);
            b.Property<string>("MetadataJson").IsRequired();
            b.Property<DateTimeOffset>("OccurredUtc");
            b.Property<string>("TargetId").HasMaxLength(200);
            b.Property<string>("TargetType").IsRequired().HasMaxLength(200);
            b.HasKey("Id");
            b.HasIndex("OccurredUtc");
            b.ToTable("AuditEvents");
        });

        modelBuilder.Entity<ControlUserRole>(b =>
        {
            b.HasOne<ControlRole>("Role")
                .WithMany("UserRoles")
                .HasForeignKey("RoleId")
                .OnDelete(DeleteBehavior.Cascade)
                .IsRequired();

            b.HasOne<ControlUser>("User")
                .WithMany("UserRoles")
                .HasForeignKey("UserId")
                .OnDelete(DeleteBehavior.Cascade)
                .IsRequired();
        });

        modelBuilder.Entity<ManagedInstance>(b =>
        {
            b.HasOne<ControlGroup>("Group")
                .WithMany("Instances")
                .HasForeignKey("GroupId")
                .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<InstanceCredential>(b =>
        {
            b.HasOne<ManagedInstance>("ManagedInstance")
                .WithMany("Credentials")
                .HasForeignKey("ManagedInstanceId")
                .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<EnrollmentRequestEntity>(b =>
        {
            b.HasOne<ManagedInstance>("ManagedInstance")
                .WithMany()
                .HasForeignKey("ManagedInstanceId")
                .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<ApplicationSchemaRecord>(b =>
        {
            b.HasOne<ControlGroup>("Group")
                .WithMany()
                .HasForeignKey("GroupId")
                .OnDelete(DeleteBehavior.Cascade)
                .IsRequired();
        });

        modelBuilder.Entity<ApplicationSettingOverride>(b =>
        {
            b.HasOne<ApplicationSchemaRecord>("ApplicationSchema")
                .WithMany("Overrides")
                .HasForeignKey("ApplicationSchemaId")
                .OnDelete(DeleteBehavior.Cascade)
                .IsRequired();
        });
    }
}
