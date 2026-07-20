using MagicControl.Web.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace MagicControl.Web.Health;

public sealed class DatabaseHealthCheck(
    IDbContextFactory<MagicControlDbContext> dbFactory) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
            return await db.Database.CanConnectAsync(cancellationToken)
                ? HealthCheckResult.Healthy("The MagicControl database is reachable.")
                : HealthCheckResult.Unhealthy("The MagicControl database is not reachable.");
        }
        catch (Exception exception)
        {
            return HealthCheckResult.Unhealthy(
                "The MagicControl database health check failed.",
                exception);
        }
    }
}
