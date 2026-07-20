using System.Security.Claims;
using MagicControl.Shared.Security;
using MagicControl.Shared.Utilities;
using MagicControl.Web.Configuration;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace MagicControl.Web.Features.Authentication;

public sealed record UserAuthenticationResult(
    bool Succeeded,
    string? Error,
    ClaimsPrincipal? Principal,
    Guid? UserId);

public sealed class UserAuthenticationService(
    IDbContextFactory<MagicControlDbContext> dbFactory,
    IPasswordHasher<ControlUser> passwordHasher,
    IOptionsMonitor<MagicControlSettings> settings)
{
    public async ValueTask<UserAuthenticationResult> AuthenticateAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
        {
            return new(false, "Invalid username or password.", null, null);
        }

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var normalized = MagicControlNameNormalizer.Normalize(username);
        var user = await db.Users
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .SingleOrDefaultAsync(x => x.NormalizedUsername == normalized, cancellationToken);

        if (user is null || user.IsDisabled)
        {
            return new(false, "Invalid username or password.", null, null);
        }

        var now = DateTimeOffset.UtcNow;
        if (user.LockoutEndUtc is { } lockout && lockout > now)
        {
            return new(false, "The account is temporarily locked.", null, null);
        }

        var verification = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);
        if (verification == PasswordVerificationResult.Failed)
        {
            user.FailedLoginCount++;
            var security = settings.CurrentValue.Security;
            if (user.FailedLoginCount >= Math.Max(1, security.MaximumFailedLogins))
            {
                user.LockoutEndUtc = now.AddMinutes(Math.Max(1, security.LockoutMinutes));
                user.FailedLoginCount = 0;
            }

            user.UpdatedUtc = now;
            await db.SaveChangesAsync(cancellationToken);
            return new(false, "Invalid username or password.", null, null);
        }

        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
        {
            user.PasswordHash = passwordHasher.HashPassword(user, password);
        }

        user.FailedLoginCount = 0;
        user.LockoutEndUtc = null;
        user.LastLoginUtc = now;
        user.UpdatedUtc = now;
        await db.SaveChangesAsync(cancellationToken);

        return new(true, null, BuildPrincipal(user), user.Id);
    }

    public async ValueTask<UserAuthenticationResult> ChangePasswordAsync(
        Guid userId,
        string currentPassword,
        string newPassword,
        string confirmPassword,
        CancellationToken cancellationToken = default)
    {
        if (newPassword != confirmPassword)
        {
            return new(false, "The new passwords do not match.", null, userId);
        }

        var minimum = Math.Max(12, settings.CurrentValue.Security.PasswordMinimumLength);
        if (newPassword.Length < minimum)
        {
            return new(false, $"The new password must be at least {minimum} characters.", null, userId);
        }

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var user = await db.Users
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);

        if (user is null || user.IsDisabled)
        {
            return new(false, "The account is unavailable.", null, userId);
        }

        if (passwordHasher.VerifyHashedPassword(user, user.PasswordHash, currentPassword)
            == PasswordVerificationResult.Failed)
        {
            return new(false, "The current password is incorrect.", null, userId);
        }

        var now = DateTimeOffset.UtcNow;
        user.PasswordHash = passwordHasher.HashPassword(user, newPassword);
        user.SecurityStamp = Guid.NewGuid().ToString("N");
        user.MustChangePassword = false;
        user.PasswordChangedUtc = now;
        user.UpdatedUtc = now;
        user.FailedLoginCount = 0;
        user.LockoutEndUtc = null;

        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = now,
            ActorType = "user",
            ActorId = user.Id.ToString("D"),
            Action = "user.password.changed",
            TargetType = "user",
            TargetId = user.Id.ToString("D")
        });

        await db.SaveChangesAsync(cancellationToken);
        return new(true, null, BuildPrincipal(user), user.Id);
    }

    public async ValueTask<ClaimsPrincipal?> RefreshPrincipalAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var user = await db.Users
            .AsNoTracking()
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);

        return user is null || user.IsDisabled ? null : BuildPrincipal(user);
    }

    public static ClaimsPrincipal BuildPrincipal(ControlUser user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString("D")),
            new(ClaimTypes.Name, user.Username),
            new(MagicControlClaimTypes.SecurityStamp, user.SecurityStamp),
            new(MagicControlClaimTypes.MustChangePassword,
                user.MustChangePassword ? bool.TrueString : bool.FalseString)
        };

        claims.AddRange(user.UserRoles.Select(x => new Claim(ClaimTypes.Role, x.Role.Name)));

        return new ClaimsPrincipal(
            new ClaimsIdentity(claims, MagicControlSecurity.UiCookieScheme));
    }
}
