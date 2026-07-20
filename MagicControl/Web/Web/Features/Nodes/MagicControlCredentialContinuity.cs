using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using MagicControl.Shared.Mesh;
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

        if (!VerifyReplacementKeyPossession(request, out var proofError))
        {
            return (null, proofError);
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

    private static bool VerifyReplacementKeyPossession(
        MagicSettingsSyncRequest request,
        out string? error)
    {
        var proof = request.Proof;
        var now = DateTimeOffset.UtcNow;
        var expectedBodyHash = MagicSettingsSyncProof.ComputeBodySha256(
            request.Identity,
            request.Manifest,
            request.LastRemoteRevision,
            request.MigrationReport,
            request.IdentityContinuityProof);

        if (proof.NodeId != request.Identity.NodeId
            || proof.CredentialId != request.Identity.CredentialId)
        {
            error = "The replacement credential proof does not match the new node identity.";
            return false;
        }

        if (!string.Equals(proof.Version, "MAGICSETTINGS-PROOF-V1", StringComparison.Ordinal)
            || !string.Equals(
                proof.Audience,
                MagicControlNodeProtocol.NodeSyncAudience,
                StringComparison.Ordinal)
            || !string.Equals(proof.Method, "POST", StringComparison.OrdinalIgnoreCase)
            || !string.Equals(
                proof.BodySha256,
                expectedBodyHash,
                StringComparison.OrdinalIgnoreCase)
            || proof.IssuedUtc - TimeSpan.FromSeconds(30) > now
            || proof.ExpiresUtc + TimeSpan.FromSeconds(30) < now
            || proof.ExpiresUtc <= proof.IssuedUtc
            || proof.ExpiresUtc - proof.IssuedUtc > TimeSpan.FromMinutes(5)
            || string.IsNullOrWhiteSpace(proof.Nonce))
        {
            error = "The replacement credential synchronization proof is structurally invalid.";
            return false;
        }

        if (!Uri.TryCreate(proof.Target, UriKind.Absolute, out var target)
            || !target.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !target.Host.Equals("magiccontrol.local", StringComparison.OrdinalIgnoreCase)
            || !target.AbsolutePath.StartsWith("/groups/", StringComparison.Ordinal)
            || !target.AbsolutePath.Contains("/contexts/", StringComparison.Ordinal)
            || !target.AbsolutePath.EndsWith("/magicsettings/sync", StringComparison.Ordinal))
        {
            error = "The replacement credential proof target is not a MagicControl synchronization endpoint.";
            return false;
        }

        var canonical = string.Join(
            "\n",
            proof.Version,
            proof.NodeId.ToString("D"),
            proof.CredentialId.ToString("D"),
            proof.Audience,
            proof.Method.ToUpperInvariant(),
            proof.Target,
            proof.BodySha256.ToLowerInvariant(),
            proof.IssuedUtc.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture),
            proof.ExpiresUtc.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture),
            proof.Nonce);

        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(
                Convert.FromBase64String(request.Identity.PublicKey),
                out _);
            if (!key.VerifyData(
                    Encoding.UTF8.GetBytes(canonical),
                    Convert.FromBase64String(proof.Signature),
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                error = "The replacement credential proof signature is invalid.";
                return false;
            }
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            error = "The replacement credential proof key or signature is malformed.";
            return false;
        }

        error = null;
        return true;
    }
}
