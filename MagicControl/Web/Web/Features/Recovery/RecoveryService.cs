using MagicControl.Shared.Security;
using MagicControl.Web.Configuration;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicControl.Web.Features.Common;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace MagicControl.Web.Features.Recovery;

public sealed record RecoveryResetResult(bool Succeeded, string? Error, string? Username, string? TemporaryPassword);

public sealed class RecoveryService(
    IDbContextFactory<MagicControlDbContext> dbFactory,
    IPasswordHasher<ControlUser> passwordHasher,
    TemporaryPasswordGenerator passwordGenerator,
    IOptionsMonitor<MagicControlSettings> settings)
{
    private static int _used;

    public bool TryConsume()
        => Interlocked.CompareExchange(ref _used, 1, 0) == 0;

    public bool ValidateToken(string? presented)
    {
        var expected = settings.CurrentValue.AdminRecovery.OneTimeToken;
        if (!settings.CurrentValue.AdminRecovery.Enabled
            || string.IsNullOrWhiteSpace(expected)
            || string.IsNullOrWhiteSpace(presented))
        {
            return false;
        }

        var left = System.Text.Encoding.UTF8.GetBytes(expected);
        var right = System.Text.Encoding.UTF8.GetBytes(presented);
        return left.Length == right.Length
               && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(left, right);
    }

    public async ValueTask<RecoveryResetResult> ResetSuperAdministratorAsync(
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var user = await db.Users
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .Where(x => !x.IsDisabled)
            .OrderBy(x => x.CreatedUtc)
            .FirstOrDefaultAsync(
                x => x.UserRoles.Any(r => r.Role.Name == MagicControlRoles.SuperAdministrator),
                cancellationToken);

        if (user is null)
        {
            return new(false, "No enabled Super Administrator account exists.", null, null);
        }

        var temporaryPassword = passwordGenerator.Generate(
            Math.Max(20, settings.CurrentValue.Security.PasswordMinimumLength));
        var now = DateTimeOffset.UtcNow;

        user.PasswordHash = passwordHasher.HashPassword(user, temporaryPassword);
        user.SecurityStamp = Guid.NewGuid().ToString("N");
        user.MustChangePassword = true;
        user.FailedLoginCount = 0;
        user.LockoutEndUtc = null;
        user.PasswordChangedUtc = now;
        user.UpdatedUtc = now;

        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = now,
            ActorType = "local-recovery",
            ActorId = "loopback",
            Action = "user.password.recovered",
            TargetType = "user",
            TargetId = user.Id.ToString("D")
        });

        await db.SaveChangesAsync(cancellationToken);
        return new(true, null, user.Username, temporaryPassword);
    }
}
