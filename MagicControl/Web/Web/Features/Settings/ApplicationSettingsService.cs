using System.Text.Json;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicSettings.Share;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Settings;

public sealed record ApplicationSettingsApplicationSummary(
    Guid Id,
    Guid GroupId,
    string GroupName,
    string ApplicationName,
    string ApplicationVersion,
    int SchemaVersion,
    string SchemaFingerprint,
    long SettingsRevision,
    DateTimeOffset UpdatedUtc);

public sealed record ApplicationSettingOverrideSummary(
    Guid Id,
    string Path,
    MagicControlSettingScopeKind ScopeKind,
    string ScopeValue,
    string? DisplayValue,
    MagicValueState ValueState,
    MagicRemoteValueDurability Durability,
    bool PersistOffline,
    bool IsSecret,
    DateTimeOffset? ExpiresUtc,
    long Revision,
    DateTimeOffset UpdatedUtc);

public sealed record ApplicationSettingsEditor(
    ApplicationSettingsApplicationSummary Application,
    MagicSettingsSchemaManifest Manifest,
    IReadOnlyList<MagicMigrationReviewItem> MigrationReviewItems,
    IReadOnlyList<ApplicationSettingOverrideSummary> Overrides);

public sealed record SaveApplicationSettingOverrideRequest(
    string Path,
    MagicControlSettingScopeKind ScopeKind,
    string? ScopeValue,
    string? Value,
    bool ExplicitNull,
    MagicRemoteValueDurability Durability,
    bool PersistOffline,
    bool IsSecret,
    DateTimeOffset? ExpiresUtc);

public sealed record MagicControlSettingsSnapshots(
    MagicRemoteSnapshot Effective,
    MagicRemoteSnapshot Offline);

public sealed class ApplicationSettingsService(
    IDbContextFactory<MagicControlDbContext> dbFactory,
    IDataProtectionProvider dataProtectionProvider)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly IDataProtector _secretProtector = dataProtectionProvider.CreateProtector(
        "MagicControl",
        "ApplicationSettingSecrets",
        "v1");

    public async ValueTask<ApplicationSchemaRecord> UpsertSchemaAsync(
        Guid groupId,
        MagicSettingsSchemaManifest manifest,
        MagicSettingsMigrationReport? migrationReport,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var record = await db.ApplicationSchemas.SingleOrDefaultAsync(
            candidate => candidate.GroupId == groupId
                         && candidate.ApplicationName == manifest.ApplicationId,
            cancellationToken);
        var now = DateTimeOffset.UtcNow;

        if (record is null)
        {
            record = new ApplicationSchemaRecord
            {
                GroupId = groupId,
                ApplicationName = manifest.ApplicationId,
                ApplicationVersion = manifest.ApplicationVersion,
                SchemaVersion = manifest.SchemaVersion,
                SchemaFingerprint = manifest.SchemaFingerprint,
                ManifestJson = JsonSerializer.Serialize(manifest, JsonOptions),
                MigrationReviewJson = JsonSerializer.Serialize(
                    migrationReport?.ReviewItems ?? [],
                    JsonOptions),
                CreatedUtc = now,
                UpdatedUtc = now
            };
            db.ApplicationSchemas.Add(record);
        }
        else
        {
            record.ApplicationVersion = manifest.ApplicationVersion;
            record.SchemaVersion = manifest.SchemaVersion;
            record.SchemaFingerprint = manifest.SchemaFingerprint;
            record.ManifestJson = JsonSerializer.Serialize(manifest, JsonOptions);
            if (migrationReport is { ReviewItems.Count: > 0 })
            {
                var existing = DeserializeReviews(record.MigrationReviewJson).ToList();
                foreach (var item in migrationReport.ReviewItems)
                {
                    if (!existing.Contains(item))
                    {
                        existing.Add(item);
                    }
                }
                record.MigrationReviewJson = JsonSerializer.Serialize(existing, JsonOptions);
            }
            record.UpdatedUtc = now;
        }

        await db.SaveChangesAsync(cancellationToken);
        return record;
    }

    public async ValueTask<MagicControlSettingsSnapshots> BuildSnapshotsAsync(
        ManagedInstance instance,
        CancellationToken cancellationToken = default)
    {
        if (instance.GroupId is null || string.IsNullOrWhiteSpace(instance.ApplicationName))
        {
            return new(MagicRemoteSnapshot.Empty, MagicRemoteSnapshot.Empty);
        }

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var schema = await db.ApplicationSchemas
            .AsNoTracking()
            .Include(candidate => candidate.Overrides)
            .SingleOrDefaultAsync(
                candidate => candidate.GroupId == instance.GroupId
                             && candidate.ApplicationName == instance.ApplicationName,
                cancellationToken);
        if (schema is null)
        {
            return new(MagicRemoteSnapshot.Empty, MagicRemoteSnapshot.Empty);
        }

        var manifest = JsonSerializer.Deserialize<MagicSettingsSchemaManifest>(
                           schema.ManifestJson,
                           JsonOptions)
                       ?? throw new InvalidDataException("The stored MagicSettings schema is invalid.");
        var allowed = manifest.Settings
            .Where(setting => setting.RemoteOverrideAllowed)
            .Select(setting => setting.Path)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var selected = schema.Overrides
            .Where(candidate => allowed.Contains(candidate.Path))
            .Where(candidate => ScopeMatches(candidate, instance))
            .Where(candidate => candidate.ExpiresUtc is null
                                || candidate.ExpiresUtc > DateTimeOffset.UtcNow)
            .GroupBy(candidate => candidate.Path, StringComparer.OrdinalIgnoreCase)
            .Select(group => group
                .OrderBy(candidate => ScopePrecedence(candidate.ScopeKind))
                .ThenBy(candidate => candidate.Revision)
                .Last())
            .Where(candidate => !candidate.IsSecret)
            .ToArray();

        var all = new Dictionary<string, MagicRemoteValue>(StringComparer.OrdinalIgnoreCase);
        var offline = new Dictionary<string, MagicRemoteValue>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in selected)
        {
            var value = ToRemoteValue(item);
            all[item.Path] = value;
            if (item.PersistOffline)
            {
                offline[item.Path] = value;
            }
        }

        var issued = DateTimeOffset.UtcNow;
        return new MagicControlSettingsSnapshots(
            new MagicRemoteSnapshot(schema.SettingsRevision, issued, all),
            new MagicRemoteSnapshot(schema.SettingsRevision, issued, offline));
    }

    public async ValueTask<MagicSecretResponse> ResolveSecretAsync(
        ManagedInstance instance,
        string name,
        CancellationToken cancellationToken = default)
    {
        if (instance.GroupId is null || string.IsNullOrWhiteSpace(instance.ApplicationName))
        {
            return new(false, null);
        }

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var schema = await db.ApplicationSchemas
            .AsNoTracking()
            .Include(candidate => candidate.Overrides)
            .SingleOrDefaultAsync(
                candidate => candidate.GroupId == instance.GroupId
                             && candidate.ApplicationName == instance.ApplicationName,
                cancellationToken);
        if (schema is null)
        {
            return new(false, null);
        }

        var selected = schema.Overrides
            .Where(candidate => candidate.IsSecret)
            .Where(candidate => string.Equals(candidate.Path, name, StringComparison.OrdinalIgnoreCase))
            .Where(candidate => ScopeMatches(candidate, instance))
            .Where(candidate => candidate.ExpiresUtc is null
                                || candidate.ExpiresUtc > DateTimeOffset.UtcNow)
            .OrderBy(candidate => ScopePrecedence(candidate.ScopeKind))
            .ThenBy(candidate => candidate.Revision)
            .LastOrDefault();

        if (selected?.ProtectedSecret is null)
        {
            return new(false, null);
        }

        return new(
            true,
            _secretProtector.Unprotect(selected.ProtectedSecret),
            selected.ExpiresUtc);
    }

    public async ValueTask<IReadOnlyList<ApplicationSettingsApplicationSummary>> GetApplicationsAsync(
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.ApplicationSchemas
            .AsNoTracking()
            .OrderBy(candidate => candidate.Group.Name)
            .ThenBy(candidate => candidate.ApplicationName)
            .Select(candidate => new ApplicationSettingsApplicationSummary(
                candidate.Id,
                candidate.GroupId,
                candidate.Group.Name,
                candidate.ApplicationName,
                candidate.ApplicationVersion,
                candidate.SchemaVersion,
                candidate.SchemaFingerprint,
                candidate.SettingsRevision,
                candidate.UpdatedUtc))
            .ToArrayAsync(cancellationToken);
    }

    public async ValueTask<ApplicationSettingsEditor> GetEditorAsync(
        Guid schemaId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var schema = await db.ApplicationSchemas
            .AsNoTracking()
            .Include(candidate => candidate.Group)
            .Include(candidate => candidate.Overrides)
            .SingleOrDefaultAsync(candidate => candidate.Id == schemaId, cancellationToken)
            ?? throw new KeyNotFoundException("The application settings schema was not found.");

        var summary = new ApplicationSettingsApplicationSummary(
            schema.Id,
            schema.GroupId,
            schema.Group.Name,
            schema.ApplicationName,
            schema.ApplicationVersion,
            schema.SchemaVersion,
            schema.SchemaFingerprint,
            schema.SettingsRevision,
            schema.UpdatedUtc);
        var manifest = JsonSerializer.Deserialize<MagicSettingsSchemaManifest>(
                           schema.ManifestJson,
                           JsonOptions)
                       ?? throw new InvalidDataException("The stored MagicSettings schema is invalid.");
        var overrides = schema.Overrides
            .OrderBy(candidate => candidate.Path, StringComparer.OrdinalIgnoreCase)
            .ThenBy(candidate => candidate.ScopeKind)
            .ThenBy(candidate => candidate.ScopeValue, StringComparer.OrdinalIgnoreCase)
            .Select(candidate => new ApplicationSettingOverrideSummary(
                candidate.Id,
                candidate.Path,
                candidate.ScopeKind,
                candidate.ScopeValue,
                candidate.IsSecret ? "••••••••" : ToDisplayValue(candidate),
                candidate.ValueState,
                candidate.Durability,
                candidate.PersistOffline,
                candidate.IsSecret,
                candidate.ExpiresUtc,
                candidate.Revision,
                candidate.UpdatedUtc))
            .ToArray();

        return new ApplicationSettingsEditor(
            summary,
            manifest,
            DeserializeReviews(schema.MigrationReviewJson),
            overrides);
    }

    public async ValueTask SaveOverrideAsync(
        Guid schemaId,
        SaveApplicationSettingOverrideRequest request,
        Guid actorUserId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var schema = await db.ApplicationSchemas
            .Include(candidate => candidate.Overrides)
            .SingleOrDefaultAsync(candidate => candidate.Id == schemaId, cancellationToken)
            ?? throw new KeyNotFoundException("The application settings schema was not found.");
        var manifest = JsonSerializer.Deserialize<MagicSettingsSchemaManifest>(
                           schema.ManifestJson,
                           JsonOptions)
                       ?? throw new InvalidDataException("The stored MagicSettings schema is invalid.");
        var setting = manifest.Settings.SingleOrDefault(candidate =>
                          string.Equals(candidate.Path, request.Path, StringComparison.OrdinalIgnoreCase))
                      ?? throw new KeyNotFoundException("The setting path is not present in the application schema.");
        if (!setting.RemoteOverrideAllowed)
        {
            throw new InvalidOperationException(
                $"The application explicitly disallows remote overrides for '{setting.Path}'.");
        }

        var scopeValue = NormalizeScopeValue(request.ScopeKind, request.ScopeValue);
        var existing = schema.Overrides.SingleOrDefault(candidate =>
            string.Equals(candidate.Path, setting.Path, StringComparison.OrdinalIgnoreCase)
            && candidate.ScopeKind == request.ScopeKind
            && string.Equals(candidate.ScopeValue, scopeValue, StringComparison.OrdinalIgnoreCase));
        var now = DateTimeOffset.UtcNow;
        schema.SettingsRevision = checked(schema.SettingsRevision + 1);
        schema.UpdatedUtc = now;

        existing ??= new ApplicationSettingOverride
        {
            ApplicationSchema = schema,
            Path = setting.Path,
            ScopeKind = request.ScopeKind,
            ScopeValue = scopeValue
        };
        if (existing.Id == Guid.Empty || !schema.Overrides.Contains(existing))
        {
            schema.Overrides.Add(existing);
        }

        existing.ValueState = request.ExplicitNull
            ? MagicValueState.Null
            : MagicValueState.Value;
        existing.Durability = request.Durability;
        existing.ExpiresUtc = request.ExpiresUtc;
        existing.Revision = schema.SettingsRevision;
        existing.UpdatedByUserId = actorUserId;
        existing.UpdatedUtc = now;
        existing.IsSecret = request.IsSecret || setting.Sensitive;
        existing.PersistOffline = !existing.IsSecret && request.PersistOffline;

        if (existing.IsSecret)
        {
            if (request.ExplicitNull)
            {
                throw new InvalidOperationException("A secret override cannot be an explicit null value.");
            }
            if (string.IsNullOrEmpty(request.Value))
            {
                throw new InvalidOperationException("A secret value is required.");
            }
            existing.ProtectedSecret = _secretProtector.Protect(request.Value);
            existing.ValueJson = null;
        }
        else
        {
            existing.ProtectedSecret = null;
            existing.ValueJson = request.ExplicitNull
                ? null
                : NormalizeJsonValue(request.Value, setting.Type);
        }

        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = now,
            ActorType = "user",
            ActorId = actorUserId.ToString("D"),
            Action = "application.settings.override.saved",
            TargetType = "application-schema",
            TargetId = schema.Id.ToString("D"),
            MetadataJson = JsonSerializer.Serialize(new
            {
                setting.Path,
                request.ScopeKind,
                ScopeValue = scopeValue,
                existing.IsSecret,
                existing.PersistOffline,
                schema.SettingsRevision
            }, JsonOptions)
        });

        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async ValueTask DeleteOverrideAsync(
        Guid overrideId,
        Guid actorUserId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var item = await db.ApplicationSettingOverrides
            .Include(candidate => candidate.ApplicationSchema)
            .SingleOrDefaultAsync(candidate => candidate.Id == overrideId, cancellationToken)
            ?? throw new KeyNotFoundException("The application setting override was not found.");
        var now = DateTimeOffset.UtcNow;
        item.ApplicationSchema.SettingsRevision = checked(item.ApplicationSchema.SettingsRevision + 1);
        item.ApplicationSchema.UpdatedUtc = now;
        db.ApplicationSettingOverrides.Remove(item);
        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = now,
            ActorType = "user",
            ActorId = actorUserId.ToString("D"),
            Action = "application.settings.override.deleted",
            TargetType = "application-schema",
            TargetId = item.ApplicationSchemaId.ToString("D"),
            MetadataJson = JsonSerializer.Serialize(new
            {
                item.Path,
                item.ScopeKind,
                item.ScopeValue,
                item.ApplicationSchema.SettingsRevision
            }, JsonOptions)
        });
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    private static bool ScopeMatches(
        ApplicationSettingOverride candidate,
        ManagedInstance instance)
        => candidate.ScopeKind switch
        {
            MagicControlSettingScopeKind.Application => true,
            MagicControlSettingScopeKind.Site => string.Equals(
                candidate.ScopeValue,
                instance.SiteName,
                StringComparison.OrdinalIgnoreCase),
            MagicControlSettingScopeKind.Role => string.Equals(
                candidate.ScopeValue,
                instance.InstanceRole,
                StringComparison.OrdinalIgnoreCase),
            MagicControlSettingScopeKind.Instance => string.Equals(
                    candidate.ScopeValue,
                    instance.Id.ToString("D"),
                    StringComparison.OrdinalIgnoreCase)
                || string.Equals(
                    candidate.ScopeValue,
                    instance.InstanceName,
                    StringComparison.OrdinalIgnoreCase),
            _ => false
        };

    private static int ScopePrecedence(MagicControlSettingScopeKind scope)
        => scope switch
        {
            MagicControlSettingScopeKind.Application => 1,
            MagicControlSettingScopeKind.Site => 2,
            MagicControlSettingScopeKind.Role => 3,
            MagicControlSettingScopeKind.Instance => 4,
            _ => 0
        };

    private static string NormalizeScopeValue(
        MagicControlSettingScopeKind scope,
        string? value)
    {
        if (scope == MagicControlSettingScopeKind.Application)
        {
            return string.Empty;
        }
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"A scope value is required for {scope} overrides.");
        }
        return value.Trim();
    }

    private static MagicRemoteValue ToRemoteValue(ApplicationSettingOverride item)
    {
        if (item.ValueState == MagicValueState.Null)
        {
            return MagicRemoteValue.ExplicitNull(item.Durability, item.ExpiresUtc);
        }

        if (string.IsNullOrWhiteSpace(item.ValueJson))
        {
            throw new InvalidDataException($"The remote value for '{item.Path}' is empty.");
        }

        using var document = JsonDocument.Parse(item.ValueJson);
        return new MagicRemoteValue(
            MagicValueState.Value,
            document.RootElement.Clone(),
            item.Durability,
            item.ExpiresUtc);
    }

    private static string? ToDisplayValue(ApplicationSettingOverride item)
    {
        if (item.ValueState == MagicValueState.Null)
        {
            return "null";
        }
        return item.ValueJson;
    }

    private static string NormalizeJsonValue(string? value, string type)
    {
        if (value is null)
        {
            throw new InvalidOperationException("A value is required unless Explicit null is selected.");
        }

        if (type.Contains("String", StringComparison.OrdinalIgnoreCase))
        {
            return JsonSerializer.Serialize(value, JsonOptions);
        }

        try
        {
            using var document = JsonDocument.Parse(value);
            return document.RootElement.GetRawText();
        }
        catch (JsonException)
        {
            return JsonSerializer.Serialize(value, JsonOptions);
        }
    }

    private static MagicRemoteSnapshot EmptySnapshot(long revision)
        => new(revision, DateTimeOffset.UtcNow, new Dictionary<string, MagicRemoteValue>());

    private static IReadOnlyList<MagicMigrationReviewItem> DeserializeReviews(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<IReadOnlyList<MagicMigrationReviewItem>>(json, JsonOptions)
                   ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
