using MagicControl.Web.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Data;

public sealed class MagicControlDbContext(DbContextOptions<MagicControlDbContext> options)
    : DbContext(options)
{
    public DbSet<ControlUser> Users => Set<ControlUser>();
    public DbSet<ControlRole> Roles => Set<ControlRole>();
    public DbSet<ControlUserRole> UserRoles => Set<ControlUserRole>();
    public DbSet<SystemState> SystemStates => Set<SystemState>();
    public DbSet<ControlGroup> Groups => Set<ControlGroup>();
    public DbSet<ManagedInstance> ManagedInstances => Set<ManagedInstance>();
    public DbSet<InstanceCredential> InstanceCredentials => Set<InstanceCredential>();
    public DbSet<EnrollmentRequestEntity> EnrollmentRequests => Set<EnrollmentRequestEntity>();
    public DbSet<ApplicationSchemaRecord> ApplicationSchemas => Set<ApplicationSchemaRecord>();
    public DbSet<ApplicationSettingOverride> ApplicationSettingOverrides => Set<ApplicationSettingOverride>();
    public DbSet<UsedProofNonce> UsedProofNonces => Set<UsedProofNonce>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ControlUser>(entity =>
        {
            entity.ToTable("Users");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Username).HasMaxLength(128).IsRequired();
            entity.Property(x => x.NormalizedUsername).HasMaxLength(128).IsRequired();
            entity.Property(x => x.PasswordHash).HasMaxLength(2048).IsRequired();
            entity.Property(x => x.SecurityStamp).HasMaxLength(128).IsRequired();
            entity.HasIndex(x => x.NormalizedUsername).IsUnique();
        });

        modelBuilder.Entity<ControlRole>(entity =>
        {
            entity.ToTable("Roles");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Name).HasMaxLength(128).IsRequired();
            entity.Property(x => x.NormalizedName).HasMaxLength(128).IsRequired();
            entity.HasIndex(x => x.NormalizedName).IsUnique();
        });

        modelBuilder.Entity<ControlUserRole>(entity =>
        {
            entity.ToTable("UserRoles");
            entity.HasKey(x => new { x.UserId, x.RoleId });
            entity.HasOne(x => x.User)
                .WithMany(x => x.UserRoles)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(x => x.Role)
                .WithMany(x => x.UserRoles)
                .HasForeignKey(x => x.RoleId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SystemState>(entity =>
        {
            entity.ToTable("SystemState");
            entity.HasKey(x => x.Key);
            entity.Property(x => x.Key).HasMaxLength(128);
            entity.Property(x => x.Value).HasMaxLength(2048).IsRequired();
        });

        modelBuilder.Entity<ControlGroup>(entity =>
        {
            entity.ToTable("Groups");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.NormalizedName).HasMaxLength(160).IsRequired();
            entity.Property(x => x.Description).HasMaxLength(2000);
            entity.Property(x => x.SecurityMode).HasConversion<string>().HasMaxLength(32);
            entity.HasIndex(x => x.NormalizedName).IsUnique();
        });

        modelBuilder.Entity<ManagedInstance>(entity =>
        {
            entity.ToTable("ManagedInstances");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Kind).HasConversion<string>().HasMaxLength(64);
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(64);
            entity.Property(x => x.DisplayName).HasMaxLength(200).IsRequired();
            entity.Property(x => x.ApplicationName).HasMaxLength(200);
            entity.Property(x => x.InstanceName).HasMaxLength(200);
            entity.Property(x => x.InstanceRole).HasMaxLength(200);
            entity.Property(x => x.SiteName).HasMaxLength(200);
            entity.Property(x => x.AdvertisedEndpoint).HasMaxLength(2048);
            entity.Property(x => x.Version).HasMaxLength(128);
            entity.Property(x => x.CapabilitiesJson).IsRequired();
            entity.Property(x => x.MetadataJson).IsRequired();
            entity.Property(x => x.EndpointsJson).IsRequired();
            entity.HasOne(x => x.Group)
                .WithMany(x => x.Instances)
                .HasForeignKey(x => x.GroupId)
                .OnDelete(DeleteBehavior.SetNull);
            entity.HasIndex(x => new { x.ApplicationName, x.InstanceName });
            entity.HasIndex(x => x.SiteName);
        });

        modelBuilder.Entity<InstanceCredential>(entity =>
        {
            entity.ToTable("InstanceCredentials");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.PublicKey).HasMaxLength(4096).IsRequired();
            entity.Property(x => x.Fingerprint).HasMaxLength(128).IsRequired();
            entity.Property(x => x.SignatureAlgorithm).HasMaxLength(128).IsRequired();
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(64);
            entity.HasOne(x => x.ManagedInstance)
                .WithMany(x => x.Credentials)
                .HasForeignKey(x => x.ManagedInstanceId)
                .OnDelete(DeleteBehavior.SetNull);
            entity.HasIndex(x => new { x.NodeId, x.CredentialId }).IsUnique();
            entity.HasIndex(x => x.Fingerprint);
        });

        modelBuilder.Entity<EnrollmentRequestEntity>(entity =>
        {
            entity.ToTable("EnrollmentRequests");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Kind).HasConversion<string>().HasMaxLength(64);
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(64);
            entity.Property(x => x.PublicKey).HasMaxLength(4096).IsRequired();
            entity.Property(x => x.Fingerprint).HasMaxLength(128).IsRequired();
            entity.Property(x => x.SignatureAlgorithm).HasMaxLength(128).IsRequired();
            entity.Property(x => x.DisplayName).HasMaxLength(200).IsRequired();
            entity.Property(x => x.ApplicationName).HasMaxLength(200);
            entity.Property(x => x.GroupName).HasMaxLength(200);
            entity.Property(x => x.InstanceName).HasMaxLength(200);
            entity.Property(x => x.InstanceRole).HasMaxLength(200);
            entity.Property(x => x.SiteName).HasMaxLength(200);
            entity.Property(x => x.Version).HasMaxLength(128);
            entity.Property(x => x.AdvertisedEndpoint).HasMaxLength(2048);
            entity.Property(x => x.BootstrapNonce).HasMaxLength(128).IsRequired();
            entity.Property(x => x.PairingCode).HasMaxLength(32).IsRequired();
            entity.Property(x => x.RequestedRolesJson).IsRequired();
            entity.Property(x => x.CapabilitiesJson).IsRequired();
            entity.Property(x => x.MetadataJson).IsRequired();
            entity.Property(x => x.EndpointsJson).IsRequired();
            entity.Property(x => x.SchemaManifestJson).IsRequired();
            entity.Property(x => x.MigrationReportJson).IsRequired();
            entity.Property(x => x.DecisionReason).HasMaxLength(2000);
            entity.HasOne(x => x.ManagedInstance)
                .WithMany()
                .HasForeignKey(x => x.ManagedInstanceId)
                .OnDelete(DeleteBehavior.SetNull);
            entity.HasIndex(x => new { x.NodeId, x.CredentialId, x.Kind }).IsUnique();
            entity.HasIndex(x => new { x.Status, x.Kind, x.LastSeenUtc });
            entity.HasIndex(x => x.GroupId);
        });

        modelBuilder.Entity<ApplicationSchemaRecord>(entity =>
        {
            entity.ToTable("ApplicationSchemas");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.ApplicationName).HasMaxLength(200).IsRequired();
            entity.Property(x => x.ApplicationVersion).HasMaxLength(128).IsRequired();
            entity.Property(x => x.SchemaFingerprint).HasMaxLength(128).IsRequired();
            entity.Property(x => x.ManifestJson).IsRequired();
            entity.Property(x => x.MigrationReviewJson).IsRequired();
            entity.HasOne(x => x.Group)
                .WithMany()
                .HasForeignKey(x => x.GroupId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(x => new { x.GroupId, x.ApplicationName }).IsUnique();
        });

        modelBuilder.Entity<ApplicationSettingOverride>(entity =>
        {
            entity.ToTable("ApplicationSettingOverrides");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Path).HasMaxLength(512).IsRequired();
            entity.Property(x => x.ScopeKind).HasConversion<string>().HasMaxLength(32);
            entity.Property(x => x.ScopeValue).HasMaxLength(256).IsRequired();
            entity.Property(x => x.ValueState).HasConversion<string>().HasMaxLength(32);
            entity.Property(x => x.Durability).HasConversion<string>().HasMaxLength(32);
            entity.Property(x => x.ValueJson);
            entity.Property(x => x.ProtectedSecret);
            entity.HasOne(x => x.ApplicationSchema)
                .WithMany(x => x.Overrides)
                .HasForeignKey(x => x.ApplicationSchemaId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(x => new
            {
                x.ApplicationSchemaId,
                x.Path,
                x.ScopeKind,
                x.ScopeValue
            }).IsUnique();
        });

        modelBuilder.Entity<UsedProofNonce>(entity =>
        {
            entity.ToTable("UsedProofNonces");
            entity.HasKey(x => new { x.CredentialId, x.Nonce });
            entity.Property(x => x.Nonce).HasMaxLength(256);
            entity.HasIndex(x => x.ExpiresUtc);
        });

        modelBuilder.Entity<AuditEvent>(entity =>
        {
            entity.ToTable("AuditEvents");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.ActorType).HasMaxLength(64);
            entity.Property(x => x.ActorId).HasMaxLength(200);
            entity.Property(x => x.Action).HasMaxLength(200).IsRequired();
            entity.Property(x => x.TargetType).HasMaxLength(200).IsRequired();
            entity.Property(x => x.TargetId).HasMaxLength(200);
            entity.Property(x => x.MetadataJson).IsRequired();
            entity.HasIndex(x => x.OccurredUtc);
        });
    }
}
