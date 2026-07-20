using System.Security.Cryptography;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicSettings.Server;
using MagicSettings.Share;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Nodes;

internal static class MagicControlCredentialContinuity
{
    public static async ValueTask<(InstanceCredential? Credential, string? Error)> TryApplyAsync(
        MagicControlDbContext db,
        MagicSettingsSyncRequest request,
        CancellationToken cancellationToken)
    {
        var continuity = request.IdentityContinuityProof;
        if (continuity is null)
        {
            return (null, null);
        }

        if (!MagicNodeProofVerifier.VerifyContinuity(continuity))
        {
            return (null, "The MagicSettings credential continuity proof is invalid.");
        }

        if (continuity.NewIdentity.NodeId != request.Identity.NodeId
            || continuity.NewIdentity.CredentialId != request.Identity.CredentialId
            || !string.Equals(
                continuity.NewIdentity.PublicKey,
                request.Identity.PublicKey,
                StringComparison.Ordinal))
        {
            return (null, "The continuity proof does not describe the synchronizing credential.");
        }

        var previous = await db.InstanceCredentials
            .Include(candidate => candidate.ManagedInstance)
            .ThenInclude(instance => instance!.Group)
            .SingleOrDefaultAsync(
                candidate => candidate.NodeId == continuity.PreviousIdentity.NodeId
                             && candidate.CredentialId == continuity.PreviousIdentity.CredentialId,
                cancellationToken);
        if (previous is null
            || previous.ManagedInstance is null
            || previous.Status is not (MagicCredentialStatus.Approved or MagicCredentialStatus.Retiring))
        {
            return (null, "The previous MagicSettings credential is not an approved managed instance credential.");
        }

        if (!string.Equals(
                previous.PublicKey,
                continuity.PreviousIdentity.PublicKey,
                StringComparison.Ordinal))
        {
            return (null, "The continuity proof does not match the registered previous public key.");
        }

        var now = DateTimeOffset.UtcNow;
        previous.Status = MagicCredentialStatus.Retiring;
        previous.RetiringUtc ??= now;
        previous.UpdatedUtc = now;

        var replacement = new InstanceCredential
        {
            NodeId = request.Identity.NodeId,
            CredentialId = request.Identity.CredentialId,
            PublicKey = request.Identity.PublicKey,
            Fingerprint = Convert.ToHexString(
                    SHA256.HashData(Convert.FromBase64String(request.Identity.PublicKey)))
                .ToLowerInvariant(),
            SignatureAlgorithm = request.Identity.SignatureAlgorithm,
            Status = MagicCredentialStatus.Approved,
            ManagedInstance = previous.ManagedInstance,
            CreatedUtc = now,
            UpdatedUtc = now
        };
        db.InstanceCredentials.Add(replacement);

        if (previous.ManagedInstance.Group is not null)
        {
            previous.ManagedInstance.Group.ManifestRevision = checked(
                Math.Max(1, previous.ManagedInstance.Group.ManifestRevision) + 1);
            previous.ManagedInstance.Group.UpdatedUtc = now;
        }

        await db.SaveChangesAsync(cancellationToken);
        return (replacement, null);
    }
}
