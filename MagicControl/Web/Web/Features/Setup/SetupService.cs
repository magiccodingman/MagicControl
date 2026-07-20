using System.Data;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using MagicControl.Shared.Security;
using MagicControl.Shared.Utilities;
using MagicControl.Web.Configuration;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace MagicControl.Web.Features.Setup;

public interface ISetupState
{
    ValueTask<bool> IsCompleteAsync(CancellationToken cancellationToken = default);
}

public sealed record InitialSetupRequest(string Username, string Password, string ConfirmPassword);
public sealed record InitialSetupResult(bool Succeeded, string? Error, Guid? UserId);

public sealed class SetupService(
    IDbContextFactory<MagicControlDbContext> dbFactory,
    IPasswordHasher<ControlUser> passwordHasher,
    IOptionsMonitor<MagicControlSettings> settings) : ISetupState
{
    public const string SetupCompleteKey = "setup-complete";

    public bool IsRequestAllowed(IPAddress? remoteAddress, string? presentedToken)
    {
        if (remoteAddress is not null && IPAddress.IsLoopback(remoteAddress))
        {
            return true;
        }

        var expected = settings.CurrentValue.Setup.RemoteSetupToken;
        if (string.IsNullOrWhiteSpace(expected) || string.IsNullOrWhiteSpace(presentedToken))
        {
            return false;
        }

        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var presentedBytes = Encoding.UTF8.GetBytes(presentedToken);
        return expectedBytes.Length == presentedBytes.Length
               && CryptographicOperations.FixedTimeEquals(expectedBytes, presentedBytes);
    }

    public async ValueTask<bool> IsCompleteAsync(CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.SystemStates.AnyAsync(x => x.Key == SetupCompleteKey, cancellationToken)
               || await db.Users.AnyAsync(cancellationToken);
    }

    public async ValueTask<InitialSetupResult> CompleteAsync(
        InitialSetupRequest request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.Username))
        {
            return new(false, "A username is required.", null);
        }

        if (request.Password != request.ConfirmPassword)
        {
            return new(false, "The passwords do not match.", null);
        }

        var minimumLength = Math.Max(12, settings.CurrentValue.Security.PasswordMinimumLength);
        if (request.Password.Length < minimumLength)
        {
            return new(
                false,
                $"The first administrator password must be at least {minimumLength} characters.",
                null);
        }

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(
            IsolationLevel.Serializable,
            cancellationToken);

        if (await db.SystemStates.AnyAsync(x => x.Key == SetupCompleteKey, cancellationToken)
            || await db.Users.AnyAsync(cancellationToken))
        {
            return new(false, "MagicControl has already been initialized.", null);
        }

        var now = DateTimeOffset.UtcNow;
        var roles = await EnsureBuiltInRolesAsync(db, now, cancellationToken);
        var normalized = MagicControlNameNormalizer.Normalize(request.Username);

        if (await db.Users.AnyAsync(x => x.NormalizedUsername == normalized, cancellationToken))
        {
            return new(false, "That username already exists.", null);
        }

        var user = new ControlUser
        {
            Username = request.Username.Trim(),
            NormalizedUsername = normalized,
            PasswordHash = string.Empty,
            SecurityStamp = Guid.NewGuid().ToString("N"),
            MustChangePassword = false,
            CreatedUtc = now,
            UpdatedUtc = now,
            PasswordChangedUtc = now
        };
        user.PasswordHash = passwordHasher.HashPassword(user, request.Password);

        db.Users.Add(user);
        db.UserRoles.Add(new ControlUserRole
        {
            User = user,
            Role = roles[MagicControlRoles.SuperAdministrator]
        });
        db.SystemStates.Add(new SystemState
        {
            Key = SetupCompleteKey,
            Value = "true",
            UpdatedUtc = now
        });
        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = now,
            ActorType = "bootstrap",
            ActorId = "first-run",
            Action = "system.setup.completed",
            TargetType = "user",
            TargetId = user.Id.ToString("D")
        });

        try
        {
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new(true, null, user.Id);
        }
        catch (DbUpdateException)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new(false, "MagicControl was initialized by another request.", null);
        }
    }

    internal static async Task<Dictionary<string, ControlRole>> EnsureBuiltInRolesAsync(
        MagicControlDbContext db,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var existing = await db.Roles.ToDictionaryAsync(
            x => x.NormalizedName,
            StringComparer.Ordinal,
            cancellationToken);

        foreach (var roleName in MagicControlRoles.BuiltIn)
        {
            var normalized = MagicControlNameNormalizer.Normalize(roleName);
            if (existing.ContainsKey(normalized))
            {
                continue;
            }

            var role = new ControlRole
            {
                Name = roleName,
                NormalizedName = normalized,
                IsBuiltIn = true,
                CreatedUtc = now
            };
            db.Roles.Add(role);
            existing[normalized] = role;
        }

        return MagicControlRoles.BuiltIn.ToDictionary(
            roleName => roleName,
            roleName => existing[MagicControlNameNormalizer.Normalize(roleName)],
            StringComparer.Ordinal);
    }
}
