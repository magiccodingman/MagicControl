using System.Text.Json;
using MagicControl.Shared.Enrollments;
using MagicControl.Shared.Mesh;
using MagicControl.Shared.Utilities;
using MagicControl.Web.Data.Entities;
using MagicSettings.Share;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Enrollments;

public sealed partial class EnrollmentService
{
    public async ValueTask<EnrollmentReceipt> ReviewAsync(
        Guid requestId,
        bool approve,
        string? reason,
        Guid reviewerUserId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var request = await db.EnrollmentRequests
            .SingleOrDefaultAsync(x => x.Id == requestId, cancellationToken)
            ?? throw new KeyNotFoundException("The enrollment request was not found.");

        if (request.Status != EnrollmentRequestStatus.Pending)
        {
            return new(request.Id, request.Status, "The request has already been reviewed.");
        }

        var credential = await db.InstanceCredentials.SingleAsync(
            x => x.NodeId == request.NodeId && x.CredentialId == request.CredentialId,
            cancellationToken);

        if (approve && credential.ManagedInstanceId is not null)
        {
            throw new InvalidOperationException(
                "The credential is already attached to a managed instance.");
        }

        var now = DateTimeOffset.UtcNow;
        request.ReviewedUtc = now;
        request.ReviewedByUserId = reviewerUserId;
        request.DecisionReason = Clean(reason, 2000);

        if (!approve)
        {
            request.Status = EnrollmentRequestStatus.Rejected;
            db.AuditEvents.Add(CreateReviewAudit(
                request,
                reviewerUserId,
                "enrollment.rejected",
                now));

            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(request.Id, request.Status, "The enrollment request was rejected.");
        }

        ControlGroup? group = null;
        if (request.Kind == EnrollmentKind.ApplicationInstance)
        {
            var normalizedGroup = MagicControlNameNormalizer.Normalize(request.GroupName!);
            group = await db.Groups.SingleOrDefaultAsync(
                x => x.NormalizedName == normalizedGroup,
                cancellationToken);

            if (group is null)
            {
                group = new ControlGroup
                {
                    Name = request.GroupName!.Trim(),
                    NormalizedName = normalizedGroup,
                    AllowOpenLocalMembers = true,
                    SecurityMode = MagicControlGroupSecurityMode.Open,
                    SecurityEpoch = Guid.NewGuid(),
                    ManifestRevision = 1,
                    CreatedUtc = now,
                    UpdatedUtc = now
                };
                db.Groups.Add(group);
            }
            else
            {
                group.ManifestRevision = checked(Math.Max(1, group.ManifestRevision) + 1);
                group.UpdatedUtc = now;
                if (group.SecurityEpoch == Guid.Empty)
                {
                    group.SecurityEpoch = Guid.NewGuid();
                }
            }
        }

        var instance = new ManagedInstance
        {
            Kind = request.Kind,
            Status = ManagedInstanceStatus.Active,
            DisplayName = request.DisplayName,
            ApplicationName = request.ApplicationName,
            InstanceName = request.InstanceName,
            InstanceRole = request.InstanceRole,
            SiteName = request.SiteName,
            AdvertisedEndpoint = request.AdvertisedEndpoint,
            Version = request.Version,
            CapabilitiesJson = request.CapabilitiesJson,
            MetadataJson = request.MetadataJson,
            Group = group,
            CreatedUtc = now,
            ApprovedUtc = now,
            LastSeenUtc = request.LastSeenUtc
        };
        db.ManagedInstances.Add(instance);

        credential.ManagedInstance = instance;
        credential.Status = MagicCredentialStatus.Approved;
        credential.UpdatedUtc = now;

        request.Status = EnrollmentRequestStatus.Approved;
        request.ManagedInstance = instance;

        db.AuditEvents.Add(CreateReviewAudit(
            request,
            reviewerUserId,
            "enrollment.approved",
            now));

        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(request.Id, request.Status, "The enrollment request was approved.");
    }

    private static AuditEvent CreateReviewAudit(
        EnrollmentRequestEntity request,
        Guid reviewerUserId,
        string action,
        DateTimeOffset now)
        => new()
        {
            OccurredUtc = now,
            ActorType = "user",
            ActorId = reviewerUserId.ToString("D"),
            Action = action,
            TargetType = request.Kind.ToString(),
            TargetId = request.Id.ToString("D"),
            MetadataJson = JsonSerializer.Serialize(new
            {
                request.NodeId,
                request.CredentialId,
                request.DecisionReason
            }, JsonOptions)
        };
}
