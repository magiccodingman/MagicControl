using MagicControl.Shared.Security;
using MagicControl.Web.Data;
using MagicControl.Web.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Setup;

public static class PrimaryAdministratorStore
{
    public const string Username = "admin";
    public const string StateKey = "primary-administrator-id";

    public static async ValueTask<Guid?> GetOrBackfillAsync(
        MagicControlDbContext db,
        CancellationToken cancellationToken = default)
    {
        var state = await db.SystemStates
            .SingleOrDefaultAsync(x => x.Key == StateKey, cancellationToken);

        if (state is not null
            && Guid.TryParse(state.Value, out var storedId)
            && await db.Users.AnyAsync(x => x.Id == storedId, cancellationToken))
        {
            return storedId;
        }

        var candidates = await db.Users
            .AsNoTracking()
            .Where(user => user.UserRoles.Any(
                assignment => assignment.Role.Name == MagicControlRoles.SuperAdministrator))
            .Select(user => new Candidate(user.Id, user.CreatedUtc))
            .ToListAsync(cancellationToken);

        if (candidates.Count == 0)
        {
            candidates = await db.Users
                .AsNoTracking()
                .Select(user => new Candidate(user.Id, user.CreatedUtc))
                .ToListAsync(cancellationToken);
        }

        var primaryId = candidates
            .OrderBy(candidate => candidate.CreatedUtc)
            .ThenBy(candidate => candidate.Id)
            .Select(candidate => (Guid?)candidate.Id)
            .FirstOrDefault();

        if (primaryId is null)
        {
            return null;
        }

        var now = DateTimeOffset.UtcNow;
        if (state is null)
        {
            db.SystemStates.Add(new SystemState
            {
                Key = StateKey,
                Value = primaryId.Value.ToString("D"),
                UpdatedUtc = now
            });
        }
        else
        {
            state.Value = primaryId.Value.ToString("D");
            state.UpdatedUtc = now;
        }

        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return primaryId;
        }
        catch (DbUpdateException)
        {
            db.ChangeTracker.Clear();
            var winningValue = await db.SystemStates
                .Where(x => x.Key == StateKey)
                .Select(x => x.Value)
                .SingleAsync(cancellationToken);

            return Guid.TryParse(winningValue, out var winningId)
                ? winningId
                : throw;
        }
    }

    private sealed record Candidate(Guid Id, DateTimeOffset CreatedUtc);
}
