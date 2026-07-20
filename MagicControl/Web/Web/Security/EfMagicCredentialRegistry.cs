using System.Security.Cryptography;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicSettings.Server;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Security;

public sealed class EfMagicCredentialRegistry(
    IDbContextFactory<MagicControlDbContext> dbFactory) : IMagicCredentialRegistry
{
    public async ValueTask<MagicRegisteredCredential?> FindAsync(
        Guid nodeId,
        Guid credentialId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var credential = await db.InstanceCredentials
            .AsNoTracking()
            .SingleOrDefaultAsync(
                x => x.NodeId == nodeId && x.CredentialId == credentialId,
                cancellationToken);

        return credential is null
            ? null
            : new MagicRegisteredCredential(
                credential.NodeId,
                credential.CredentialId,
                credential.PublicKey,
                credential.Status,
                credential.UpdatedUtc);
    }

    public async ValueTask UpsertAsync(
        MagicRegisteredCredential credential,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var existing = await db.InstanceCredentials.SingleOrDefaultAsync(
            x => x.NodeId == credential.NodeId && x.CredentialId == credential.CredentialId,
            cancellationToken);

        if (existing is null)
        {
            existing = new InstanceCredential
            {
                NodeId = credential.NodeId,
                CredentialId = credential.CredentialId,
                PublicKey = credential.PublicKey,
                Fingerprint = ComputeFingerprint(credential.PublicKey),
                SignatureAlgorithm = "ECDSA_P256_SHA256_P1363",
                Status = credential.Status,
                CreatedUtc = credential.UpdatedUtc,
                UpdatedUtc = credential.UpdatedUtc
            };
            db.InstanceCredentials.Add(existing);
        }
        else
        {
            existing.PublicKey = credential.PublicKey;
            existing.Fingerprint = ComputeFingerprint(credential.PublicKey);
            existing.Status = credential.Status;
            existing.UpdatedUtc = credential.UpdatedUtc;
        }

        await db.SaveChangesAsync(cancellationToken);
    }

    private static string ComputeFingerprint(string publicKey)
        => Convert.ToHexString(
                SHA256.HashData(Convert.FromBase64String(publicKey)))
            .ToLowerInvariant();
}
