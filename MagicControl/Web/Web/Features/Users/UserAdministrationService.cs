using MagicControl.Shared.Security;
using MagicControl.Shared.Utilities;
using MagicControl.Web.Configuration;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using MagicControl.Web.Features.Common;
using MagicControl.Web.Features.Setup;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace MagicControl.Web.Features.Users;

public sealed record UserSummary(
    Guid Id,
    string Username,
    bool IsDisabled,
    bool MustChangePassword,
    IReadOnlyList<string> Roles,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? LastLoginUtc,
    DateTimeOffset? LockoutEndUtc);

public sealed record CreateUserRequest(string Username, IReadOnlyList<string> Roles);
public sealed record TemporaryPasswordResult(Guid UserId, string Username, string TemporaryPassword);

public sealed class UserAdministrationService(
    IDbContextFactory<MagicControlDbContext> dbFactory,
    IPasswordHasher<ControlUser> passwordHasher,
    TemporaryPasswordGenerator passwordGenerator,
    IOptionsMonitor<MagicControlSettings> settings)
{
    public async ValueTask<IReadOnlyList<UserSummary>> GetUsersAsync(
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        return await db.Users
            .AsNoTracking()
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .OrderBy(x => x.Username)
            .Select(x => new UserSummary(
                x.Id,
                x.Username,
                x.IsDisabled,
                x.MustChangePassword,
                x.UserRoles.Select(r => r.Role.Name).OrderBy(r => r).ToArray(),
                x.CreatedUtc,
                x.LastLoginUtc,
                x.LockoutEndUtc))
            .ToListAsync(cancellationToken);
    }

    public async ValueTask<TemporaryPasswordResult> CreateAsync(
        CreateUserRequest request,
        Guid actorUserId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.Username))
        {
            throw new ArgumentException("A username is required.", nameof(request));
        }

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var normalized = MagicControlNameNormalizer.Normalize(request.Username);
        if (await db.Users.AnyAsync(x => x.NormalizedUsername == normalized, cancellationToken))
        {
            throw new InvalidOperationException("That username already exists.");
        }

        var now = DateTimeOffset.UtcNow;
        var roles = await SetupService.EnsureBuiltInRolesAsync(db, now, cancellationToken);
        var requestedRoles = request.Roles.Count == 0
            ? [MagicControlRoles.Viewer]
            : request.Roles.Distinct(StringComparer.Ordinal).ToArray();

        foreach (var role in requestedRoles)
        {
            if (!roles.ContainsKey(role))
            {
                throw new ArgumentException($"Unknown role '{role}'.", nameof(request));
            }
        }

        var temporaryPassword = passwordGenerator.Generate(
            Math.Max(20, settings.CurrentValue.Security.PasswordMinimumLength));

        var user = new ControlUser
        {
            Username = request.Username.Trim(),
            NormalizedUsername = normalized,
            PasswordHash = string.Empty,
            SecurityStamp = Guid.NewGuid().ToString("N"),
            MustChangePassword = true,
            CreatedUtc = now,
            UpdatedUtc = now,
            PasswordChangedUtc = now
        };
        user.PasswordHash = passwordHasher.HashPassword(user, temporaryPassword);
        db.Users.Add(user);

        foreach (var role in requestedRoles)
        {
            db.UserRoles.Add(new ControlUserRole { User = user, Role = roles[role] });
        }

        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = now,
            ActorType = "user",
            ActorId = actorUserId.ToString("D"),
            Action = "user.created",
            TargetType = "user",
            TargetId = user.Id.ToString("D"),
            MetadataJson = System.Text.Json.JsonSerializer.Serialize(new { Roles = requestedRoles })
        });

        await db.SaveChangesAsync(cancellationToken);
        return new(user.Id, user.Username, temporaryPassword);
    }

    public async ValueTask<TemporaryPasswordResult> ResetPasswordAsync(
        Guid userId,
        Guid actorUserId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken)
                   ?? throw new KeyNotFoundException("The user was not found.");

        var temporaryPassword = passwordGenerator.Generate(
            Math.Max(20, settings.CurrentValue.Security.PasswordMinimumLength));
        var now = DateTimeOffset.UtcNow;

        user.PasswordHash = passwordHasher.HashPassword(user, temporaryPassword);
        user.SecurityStamp = Guid.NewGuid().ToString("N");
        user.MustChangePassword = true;
        user.PasswordChangedUtc = now;
        user.UpdatedUtc = now;
        user.FailedLoginCount = 0;
        user.LockoutEndUtc = null;

        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = now,
            ActorType = "user",
            ActorId = actorUserId.ToString("D"),
            Action = "user.password.reset",
            TargetType = "user",
            TargetId = user.Id.ToString("D")
        });

        await db.SaveChangesAsync(cancellationToken);
        return new(user.Id, user.Username, temporaryPassword);
    }

    public async ValueTask SetDisabledAsync(
        Guid userId,
        bool disabled,
        Guid actorUserId,
        CancellationToken cancellationToken = default)
    {
        if (userId == actorUserId && disabled)
        {
            throw new InvalidOperationException("You cannot disable your own account.");
        }

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var user = await db.Users
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .SingleOrDefaultAsync(x => x.Id == userId, cancellationToken)
                   ?? throw new KeyNotFoundException("The user was not found.");

        if (disabled
            && user.UserRoles.Any(x => x.Role.Name == MagicControlRoles.SuperAdministrator)
            && !await HasAnotherEnabledSuperAdministratorAsync(db, user.Id, cancellationToken))
        {
            throw new InvalidOperationException(
                "The last enabled Super Administrator cannot be disabled.");
        }

        user.IsDisabled = disabled;
        user.SecurityStamp = Guid.NewGuid().ToString("N");
        user.UpdatedUtc = DateTimeOffset.UtcNow;

        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = user.UpdatedUtc,
            ActorType = "user",
            ActorId = actorUserId.ToString("D"),
            Action = disabled ? "user.disabled" : "user.enabled",
            TargetType = "user",
            TargetId = user.Id.ToString("D")
        });

        await db.SaveChangesAsync(cancellationToken);
    }

    public async ValueTask SetRolesAsync(
        Guid userId,
        IReadOnlyCollection<string> roleNames,
        Guid actorUserId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var user = await db.Users
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .SingleOrDefaultAsync(x => x.Id == userId, cancellationToken)
                   ?? throw new KeyNotFoundException("The user was not found.");

        var now = DateTimeOffset.UtcNow;
        var roles = await SetupService.EnsureBuiltInRolesAsync(db, now, cancellationToken);
        var selected = roleNames.Distinct(StringComparer.Ordinal).ToArray();

        if (selected.Any(x => !roles.ContainsKey(x)))
        {
            throw new ArgumentException("One or more roles are unknown.", nameof(roleNames));
        }

        var removesSuperAdministrator =
            user.UserRoles.Any(x => x.Role.Name == MagicControlRoles.SuperAdministrator)
            && !selected.Contains(MagicControlRoles.SuperAdministrator, StringComparer.Ordinal);

        if (userId == actorUserId && removesSuperAdministrator)
        {
            throw new InvalidOperationException("You cannot remove your own Super Administrator role.");
        }

        if (removesSuperAdministrator
            && !await HasAnotherEnabledSuperAdministratorAsync(db, user.Id, cancellationToken))
        {
            throw new InvalidOperationException(
                "The last enabled Super Administrator cannot lose that role.");
        }

        var selectedRoleIds = selected
            .Select(role => roles[role].Id)
            .ToHashSet();

        var removed = user.UserRoles
            .Where(existing => !selectedRoleIds.Contains(existing.RoleId))
            .ToArray();
        db.UserRoles.RemoveRange(removed);

        var existingRoleIds = user.UserRoles
            .Select(existing => existing.RoleId)
            .ToHashSet();
        foreach (var role in selected)
        {
            var roleId = roles[role].Id;
            if (!existingRoleIds.Contains(roleId))
            {
                db.UserRoles.Add(new ControlUserRole { UserId = user.Id, RoleId = roleId });
            }
        }

        user.SecurityStamp = Guid.NewGuid().ToString("N");
        user.UpdatedUtc = now;

        db.AuditEvents.Add(new AuditEvent
        {
            OccurredUtc = now,
            ActorType = "user",
            ActorId = actorUserId.ToString("D"),
            Action = "user.roles.changed",
            TargetType = "user",
            TargetId = user.Id.ToString("D"),
            MetadataJson = System.Text.Json.JsonSerializer.Serialize(new { Roles = selected })
        });

        await db.SaveChangesAsync(cancellationToken);
    }

    private static Task<bool> HasAnotherEnabledSuperAdministratorAsync(
        MagicControlDbContext db,
        Guid excludedUserId,
        CancellationToken cancellationToken)
        => db.Users.AnyAsync(
            user => user.Id != excludedUserId
                    && !user.IsDisabled
                    && user.UserRoles.Any(assignment =>
                        assignment.Role.Name == MagicControlRoles.SuperAdministrator),
            cancellationToken);
}
