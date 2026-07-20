using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicSettings.Server;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Security;

public sealed class EfMagicReplayCache(
    IDbContextFactory<MagicControlDbContext> dbFactory) : IMagicReplayCache
{
    public async ValueTask<bool> TryUseAsync(
        Guid credentialId,
        string nonce,
        DateTimeOffset expiresUtc,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var now = DateTimeOffset.UtcNow;

        await db.UsedProofNonces
            .Where(x => x.ExpiresUtc < now)
            .ExecuteDeleteAsync(cancellationToken);

        db.UsedProofNonces.Add(new UsedProofNonce
        {
            CredentialId = credentialId,
            Nonce = nonce,
            ExpiresUtc = expiresUtc,
            UsedUtc = now
        });

        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException)
        {
            return false;
        }
    }
}
