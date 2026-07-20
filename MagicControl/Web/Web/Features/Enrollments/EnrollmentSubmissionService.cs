using System.Text.Json;
using MagicControl.Shared.Enrollments;
using MagicControl.Web.Data.Entities;
using MagicSettings.Share;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Enrollments;

public sealed partial class EnrollmentService
{
    public async ValueTask<EnrollmentReceipt> SubmitVerifiedAsync(
        EnrollmentSubmission submission,
        CancellationToken cancellationToken = default)
    {
        Validate(submission);

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var now = DateTimeOffset.UtcNow;
        var identity = submission.Identity;

        var credential = await db.InstanceCredentials.SingleOrDefaultAsync(
            x => x.NodeId == identity.NodeId && x.CredentialId == identity.CredentialId,
            cancellationToken);

        if (credential is null)
        {
            credential = new InstanceCredential
            {
                NodeId = identity.NodeId,
                CredentialId = identity.CredentialId,
                PublicKey = identity.PublicKey,
                Fingerprint = identity.Fingerprint.ToLowerInvariant(),
                SignatureAlgorithm = identity.SignatureAlgorithm,
                Status = MagicCredentialStatus.Pending,
                CreatedUtc = now,
                UpdatedUtc = now
            };
            db.InstanceCredentials.Add(credential);
        }
        else if (!string.Equals(credential.PublicKey, identity.PublicKey, StringComparison.Ordinal)
                 || !string.Equals(
                     credential.Fingerprint,
                     identity.Fingerprint,
                     StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The credential identifier is already registered with different public-key material.");
        }

        var conflictingRequest = await db.EnrollmentRequests
            .AsNoTracking()
            .AnyAsync(
                x => x.NodeId == identity.NodeId
                     && x.CredentialId == identity.CredentialId
                     && x.Kind != submission.Kind,
                cancellationToken);
        if (conflictingRequest)
        {
            throw new InvalidOperationException(
                "One credential cannot enroll as both a Mesh API and an application instance.");
        }

        var request = await db.EnrollmentRequests.SingleOrDefaultAsync(
            x => x.NodeId == identity.NodeId
                 && x.CredentialId == identity.CredentialId
                 && x.Kind == submission.Kind,
            cancellationToken);

        if (credential.ManagedInstanceId is not null
            && request?.Status != EnrollmentRequestStatus.Approved)
        {
            throw new InvalidOperationException(
                "The credential is already attached to another managed instance.");
        }

        if (request is null)
        {
            request = new EnrollmentRequestEntity
            {
                Kind = submission.Kind,
                Status = EnrollmentRequestStatus.Pending,
                NodeId = identity.NodeId,
                CredentialId = identity.CredentialId,
                PublicKey = identity.PublicKey,
                Fingerprint = identity.Fingerprint.ToLowerInvariant(),
                SignatureAlgorithm = identity.SignatureAlgorithm,
                DisplayName = Clean(submission.DisplayName, 200)!,
                FirstSeenUtc = now,
                LastSeenUtc = now
            };
            db.EnrollmentRequests.Add(request);
        }

        request.LastSeenUtc = now;
        request.DisplayName = Clean(submission.DisplayName, 200)!;
        request.ApplicationName = Clean(submission.ApplicationName, 200);
        request.GroupName = Clean(submission.GroupName, 200);
        request.InstanceName = Clean(submission.InstanceName, 200);
        request.InstanceRole = Clean(submission.InstanceRole, 200);
        request.SiteName = Clean(submission.SiteName, 200);
        request.Version = Clean(submission.Version, 128);
        request.AdvertisedEndpoint = Clean(submission.AdvertisedEndpoint, 2048);
        request.RequestedRolesJson = JsonSerializer.Serialize(submission.RequestedRoles, JsonOptions);
        request.CapabilitiesJson = JsonSerializer.Serialize(submission.Capabilities, JsonOptions);
        request.MetadataJson = JsonSerializer.Serialize(submission.Metadata, JsonOptions);

        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = now,
            ActorType = "node",
            ActorId = identity.NodeId.ToString("D"),
            Action = request.Status == EnrollmentRequestStatus.Pending
                ? "enrollment.requested"
                : "enrollment.checked",
            TargetType = submission.Kind.ToString(),
            TargetId = request.Id.ToString("D"),
            MetadataJson = JsonSerializer.Serialize(new
            {
                identity.CredentialId,
                identity.Fingerprint,
                submission.DisplayName
            }, JsonOptions)
        });

        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new(
            request.Id,
            request.Status,
            request.Status switch
            {
                EnrollmentRequestStatus.Pending => "The enrollment request is pending administrator approval.",
                EnrollmentRequestStatus.Approved => "The identity is already approved.",
                _ => "The enrollment request was rejected."
            });
    }

    private static void Validate(EnrollmentSubmission submission)
    {
        ArgumentNullException.ThrowIfNull(submission);
        ArgumentNullException.ThrowIfNull(submission.Identity);

        if (string.IsNullOrWhiteSpace(submission.DisplayName))
        {
            throw new ArgumentException("DisplayName is required.", nameof(submission));
        }

        if (submission.Kind == EnrollmentKind.ApplicationInstance)
        {
            if (string.IsNullOrWhiteSpace(submission.ApplicationName)
                || string.IsNullOrWhiteSpace(submission.GroupName)
                || string.IsNullOrWhiteSpace(submission.InstanceRole))
            {
                throw new ArgumentException(
                    "ApplicationName, GroupName, and InstanceRole are required for application enrollment.",
                    nameof(submission));
            }
        }
        else if (submission.Kind == EnrollmentKind.MeshApi)
        {
            if (string.IsNullOrWhiteSpace(submission.SiteName)
                || string.IsNullOrWhiteSpace(submission.AdvertisedEndpoint))
            {
                throw new ArgumentException(
                    "SiteName and AdvertisedEndpoint are required for Mesh API enrollment.",
                    nameof(submission));
            }
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(submission), "Unsupported enrollment kind.");
        }

        if (!string.IsNullOrWhiteSpace(submission.AdvertisedEndpoint))
        {
            if (!Uri.TryCreate(submission.AdvertisedEndpoint, UriKind.Absolute, out var endpoint))
            {
                throw new ArgumentException("AdvertisedEndpoint must be an absolute URI.", nameof(submission));
            }

            var loopbackHttp = endpoint.Scheme == Uri.UriSchemeHttp && endpoint.IsLoopback;
            if (endpoint.Scheme != Uri.UriSchemeHttps && !loopbackHttp)
            {
                throw new ArgumentException(
                    "AdvertisedEndpoint must use HTTPS, except for loopback HTTP.",
                    nameof(submission));
            }
        }
    }

    private static string? Clean(string? value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var cleaned = value.Trim();
        if (cleaned.Length > maximumLength)
        {
            throw new ArgumentException($"A value exceeds the maximum length of {maximumLength}.");
        }

        return cleaned;
    }
}
