using System.Security.Cryptography;
using System.Text.Json;
using MagicControl.Shared.Enrollments;
using MagicControl.Shared.Mesh;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicControl.Web.Features.Mesh;
using MagicControl.Web.Features.Settings;
using MagicSettings.Server;
using MagicSettings.Share;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Nodes;

public sealed class MagicControlNodeSyncService(
    IDbContextFactory<MagicControlDbContext> dbFactory,
    MagicNodeProofVerifier proofVerifier,
    MeshManifestService manifests,
    ApplicationSettingsService settingsService)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async ValueTask<MagicControlNodeSyncResponse> SynchronizeAsync(
        MagicControlNodeSyncRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.GroupId == Guid.Empty
            || string.IsNullOrWhiteSpace(request.ApplicationName)
            || string.IsNullOrWhiteSpace(request.BootstrapNonce))
        {
            return Faulted(request, "GroupId, ApplicationName, and BootstrapNonce are required.");
        }

        if (!string.Equals(
                request.ApplicationName,
                request.Settings.Manifest.ApplicationId,
                StringComparison.Ordinal))
        {
            return Faulted(
                request,
                "The MagicControl application name must match the MagicSettings ApplicationId.");
        }

        var proofRequest = CreateSyncProofRequest(request);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var group = await db.Groups.SingleOrDefaultAsync(
            candidate => candidate.Id == request.GroupId,
            cancellationToken);
        if (group is null)
        {
            return Faulted(
                request,
                "The configured MagicControl group does not exist on this authority.");
        }

        var credential = await db.InstanceCredentials
            .Include(candidate => candidate.ManagedInstance)
            .ThenInclude(instance => instance!.Group)
            .SingleOrDefaultAsync(
                candidate => candidate.NodeId == request.Settings.Identity.NodeId
                             && candidate.CredentialId == request.Settings.Identity.CredentialId,
                cancellationToken);

        if (credential is null)
        {
            var verification = await proofVerifier.VerifyEnrollmentAsync(
                request.Settings.Identity,
                proofRequest,
                cancellationToken);
            if (!verification.IsValid)
            {
                return Faulted(request, verification.Error ?? "The enrollment proof is invalid.");
            }

            credential = new InstanceCredential
            {
                NodeId = request.Settings.Identity.NodeId,
                CredentialId = request.Settings.Identity.CredentialId,
                PublicKey = request.Settings.Identity.PublicKey,
                Fingerprint = Fingerprint(request.Settings.Identity.PublicKey),
                SignatureAlgorithm = request.Settings.Identity.SignatureAlgorithm,
                Status = MagicCredentialStatus.Pending,
                CreatedUtc = DateTimeOffset.UtcNow,
                UpdatedUtc = DateTimeOffset.UtcNow
            };
            db.InstanceCredentials.Add(credential);
            var enrollment = await UpsertPendingRequestAsync(
                db,
                group,
                request,
                credential,
                cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            return Pending(request, enrollment.PairingCode);
        }

        if (!string.Equals(
                credential.PublicKey,
                request.Settings.Identity.PublicKey,
                StringComparison.Ordinal))
        {
            return Faulted(request, "The supplied public key does not match the registered credential.");
        }

        if (credential.Status == MagicCredentialStatus.Pending
            || credential.ManagedInstance is null)
        {
            var verification = await proofVerifier.VerifyEnrollmentAsync(
                request.Settings.Identity,
                proofRequest,
                cancellationToken);
            if (!verification.IsValid)
            {
                return Faulted(request, verification.Error ?? "The pending enrollment proof is invalid.");
            }

            var enrollment = await UpsertPendingRequestAsync(
                db,
                group,
                request,
                credential,
                cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            return enrollment.Status switch
            {
                EnrollmentRequestStatus.Rejected => Rejected(
                    request,
                    enrollment.PairingCode,
                    enrollment.DecisionReason ?? "The enrollment request was rejected."),
                _ => Pending(request, enrollment.PairingCode)
            };
        }

        if (credential.Status == MagicCredentialStatus.Revoked)
        {
            return Rejected(request, null, "The MagicControl node credential is revoked.");
        }

        var verificationResult = await proofVerifier.VerifyAsync(
            proofRequest,
            cancellationToken);
        if (!verificationResult.IsValid)
        {
            return Faulted(request, verificationResult.Error ?? "The node synchronization proof is invalid.");
        }

        var instance = credential.ManagedInstance;
        if (instance.Status != ManagedInstanceStatus.Active
            || instance.GroupId != request.GroupId
            || !string.Equals(
                instance.ApplicationName,
                request.ApplicationName,
                StringComparison.OrdinalIgnoreCase))
        {
            return Rejected(
                request,
                null,
                "The approved credential is not an active member of the configured group and application.");
        }

        var now = DateTimeOffset.UtcNow;
        var endpointsJson = JsonSerializer.Serialize(request.Endpoints, JsonOptions);
        var directoryChanged = !string.Equals(
            instance.EndpointsJson,
            endpointsJson,
            StringComparison.Ordinal);
        instance.DisplayName = request.DisplayName.Trim();
        instance.InstanceName = Clean(request.InstanceName, 200);
        instance.InstanceRole = Clean(request.InstanceRole, 200);
        instance.SiteName = Clean(request.SiteName, 200);
        instance.Version = Clean(request.Version, 128);
        instance.EndpointsJson = endpointsJson;
        instance.AdvertisedEndpoint = request.Endpoints.FirstOrDefault()?.Uri.AbsoluteUri;
        instance.DirectorySequence = checked(instance.DirectorySequence + 1);
        instance.LastSeenUtc = now;

        if (directoryChanged && instance.Group is not null)
        {
            instance.Group.ManifestRevision = checked(
                Math.Max(1, instance.Group.ManifestRevision) + 1);
            instance.Group.UpdatedUtc = now;
        }

        await db.SaveChangesAsync(cancellationToken);
        await settingsService.UpsertSchemaAsync(
            request.GroupId,
            request.Settings.Manifest,
            request.Settings.MigrationReport,
            cancellationToken);

        var snapshots = await settingsService.BuildSnapshotsAsync(instance, cancellationToken);
        var manifest = await manifests.GetSignedManifestAsync(request.GroupId, cancellationToken);
        return new MagicControlNodeSyncResponse(
            MagicControlEnrollmentState.Approved,
            new MagicSettingsSyncResponse(
                MagicControlPlaneState.Active,
                snapshots.Effective,
                "MagicControl approval and settings are active."),
            snapshots.Offline,
            manifest,
            request.BootstrapNonce,
            [],
            PairingCode: null,
            Message: "MagicControl approval and settings are active.",
            SuggestedPollInterval: TimeSpan.FromSeconds(30));
    }

    public async ValueTask<MagicSecretResponse> ResolveSecretAsync(
        MagicControlNodeSecretRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var credential = await db.InstanceCredentials
            .AsNoTracking()
            .Include(candidate => candidate.ManagedInstance)
            .SingleOrDefaultAsync(
                candidate => candidate.NodeId == request.Secret.NodeId
                             && candidate.CredentialId == request.Secret.CredentialId,
                cancellationToken);
        var instance = credential?.ManagedInstance;
        if (credential is null
            || instance is null
            || credential.Status is not (MagicCredentialStatus.Approved or MagicCredentialStatus.Retiring)
            || instance.Status != ManagedInstanceStatus.Active
            || instance.GroupId != request.GroupId
            || !string.Equals(
                instance.ApplicationName,
                request.ApplicationName,
                StringComparison.OrdinalIgnoreCase))
        {
            return new(false, null);
        }

        var verification = await proofVerifier.VerifyAsync(
            new MagicProofVerificationRequest(
                request.Secret.Proof,
                MagicControlNodeProtocol.NodeSyncAudience,
                "POST",
                MagicControlLogicalUris.SecretResolve(request.GroupId),
                MagicSecretProof.ComputeBodySha256(request.Secret.Name),
                DateTimeOffset.UtcNow),
            cancellationToken);
        if (!verification.IsValid)
        {
            return new(false, null);
        }

        return await settingsService.ResolveSecretAsync(
            instance,
            request.Secret.Name,
            cancellationToken);
    }

    private async ValueTask<EnrollmentRequestEntity> UpsertPendingRequestAsync(
        MagicControlDbContext db,
        ControlGroup group,
        MagicControlNodeSyncRequest request,
        InstanceCredential credential,
        CancellationToken cancellationToken)
    {
        var enrollment = await db.EnrollmentRequests.SingleOrDefaultAsync(
            candidate => candidate.NodeId == request.Settings.Identity.NodeId
                         && candidate.CredentialId == request.Settings.Identity.CredentialId
                         && candidate.Kind == EnrollmentKind.ApplicationInstance,
            cancellationToken);
        var now = DateTimeOffset.UtcNow;
        var pairingCode = PairingCode(request, credential.Fingerprint);
        var capabilities = request.RequestedCapabilities
            .Distinct(StringComparer.Ordinal)
            .ToDictionary(capability => capability, _ => "requested", StringComparer.Ordinal);

        if (enrollment is null)
        {
            enrollment = new EnrollmentRequestEntity
            {
                Kind = EnrollmentKind.ApplicationInstance,
                Status = EnrollmentRequestStatus.Pending,
                NodeId = request.Settings.Identity.NodeId,
                CredentialId = request.Settings.Identity.CredentialId,
                PublicKey = request.Settings.Identity.PublicKey,
                Fingerprint = credential.Fingerprint,
                SignatureAlgorithm = request.Settings.Identity.SignatureAlgorithm,
                DisplayName = request.DisplayName.Trim(),
                ApplicationName = request.ApplicationName.Trim(),
                GroupId = group.Id,
                GroupName = group.Name,
                InstanceName = Clean(request.InstanceName, 200),
                InstanceRole = Clean(request.InstanceRole, 200),
                SiteName = Clean(request.SiteName, 200),
                Version = Clean(request.Version, 128),
                AdvertisedEndpoint = request.Endpoints.FirstOrDefault()?.Uri.AbsoluteUri,
                BootstrapNonce = request.BootstrapNonce,
                PairingCode = pairingCode,
                CapabilitiesJson = JsonSerializer.Serialize(capabilities, JsonOptions),
                EndpointsJson = JsonSerializer.Serialize(request.Endpoints, JsonOptions),
                SchemaManifestJson = JsonSerializer.Serialize(request.Settings.Manifest, JsonOptions),
                MigrationReportJson = JsonSerializer.Serialize(
                    request.Settings.MigrationReport,
                    JsonOptions),
                FirstSeenUtc = now,
                LastSeenUtc = now
            };
            db.EnrollmentRequests.Add(enrollment);
        }
        else
        {
            enrollment.DisplayName = request.DisplayName.Trim();
            enrollment.ApplicationName = request.ApplicationName.Trim();
            enrollment.GroupId = group.Id;
            enrollment.GroupName = group.Name;
            enrollment.InstanceName = Clean(request.InstanceName, 200);
            enrollment.InstanceRole = Clean(request.InstanceRole, 200);
            enrollment.SiteName = Clean(request.SiteName, 200);
            enrollment.Version = Clean(request.Version, 128);
            enrollment.AdvertisedEndpoint = request.Endpoints.FirstOrDefault()?.Uri.AbsoluteUri;
            enrollment.BootstrapNonce = request.BootstrapNonce;
            enrollment.PairingCode = pairingCode;
            enrollment.CapabilitiesJson = JsonSerializer.Serialize(capabilities, JsonOptions);
            enrollment.EndpointsJson = JsonSerializer.Serialize(request.Endpoints, JsonOptions);
            enrollment.SchemaManifestJson = JsonSerializer.Serialize(request.Settings.Manifest, JsonOptions);
            enrollment.MigrationReportJson = JsonSerializer.Serialize(
                request.Settings.MigrationReport,
                JsonOptions);
            enrollment.LastSeenUtc = now;
        }

        return enrollment;
    }

    private static MagicProofVerificationRequest CreateSyncProofRequest(
        MagicControlNodeSyncRequest request)
        => new(
            request.Settings.Proof,
            MagicControlNodeProtocol.NodeSyncAudience,
            "POST",
            MagicControlLogicalUris.SettingsSync(request.GroupId),
            MagicSettingsSyncProof.ComputeBodySha256(
                request.Settings.Identity,
                request.Settings.Manifest,
                request.Settings.LastRemoteRevision,
                request.Settings.MigrationReport,
                request.Settings.IdentityContinuityProof),
            DateTimeOffset.UtcNow);

    private static MagicControlNodeSyncResponse Pending(
        MagicControlNodeSyncRequest request,
        string pairingCode)
        => new(
            MagicControlEnrollmentState.PendingApproval,
            new MagicSettingsSyncResponse(
                MagicControlPlaneState.PendingApproval,
                MagicRemoteSnapshot.Empty,
                "The node credential is waiting for administrator approval."),
            MagicRemoteSnapshot.Empty,
            null,
            request.BootstrapNonce,
            [],
            pairingCode,
            $"Waiting for administrator approval. Pairing code: {pairingCode}",
            TimeSpan.FromSeconds(10));

    private static MagicControlNodeSyncResponse Rejected(
        MagicControlNodeSyncRequest request,
        string? pairingCode,
        string message)
        => new(
            MagicControlEnrollmentState.Rejected,
            new MagicSettingsSyncResponse(
                MagicControlPlaneState.Faulted,
                MagicRemoteSnapshot.Empty,
                message),
            MagicRemoteSnapshot.Empty,
            null,
            request.BootstrapNonce,
            [],
            pairingCode,
            message);

    private static MagicControlNodeSyncResponse Faulted(
        MagicControlNodeSyncRequest request,
        string message)
        => new(
            MagicControlEnrollmentState.Faulted,
            new MagicSettingsSyncResponse(
                MagicControlPlaneState.Faulted,
                MagicRemoteSnapshot.Empty,
                message),
            MagicRemoteSnapshot.Empty,
            null,
            request.BootstrapNonce,
            [],
            null,
            message);

    private static string PairingCode(
        MagicControlNodeSyncRequest request,
        string fingerprint)
    {
        var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
            $"{request.BootstrapNonce}:{fingerprint}:{request.GroupId:D}"));
        var code = Convert.ToHexString(bytes.AsSpan(0, 4));
        return $"{code[..4]}-{code[4..]}";
    }

    private static string Fingerprint(string publicKey)
        => Convert.ToHexString(
                SHA256.HashData(Convert.FromBase64String(publicKey)))
            .ToLowerInvariant();

    private static string? Clean(string? value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return trimmed.Length <= maximumLength
            ? trimmed
            : trimmed[..maximumLength];
    }
}
