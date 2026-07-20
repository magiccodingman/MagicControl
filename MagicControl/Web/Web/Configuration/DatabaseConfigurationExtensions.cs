using MagicControl.Web.Data;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Configuration;

public static class DatabaseConfigurationExtensions
{
    public static IServiceCollection AddMagicControlDatabase(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var provider = configuration["Database:Provider"]?.Trim() ?? "Sqlite";

        void Configure(DbContextOptionsBuilder options)
        {
            if (provider.Equals("PostgreSql", StringComparison.OrdinalIgnoreCase)
                || provider.Equals("Postgres", StringComparison.OrdinalIgnoreCase))
            {
                var connection = configuration["Database:PostgreSqlConnectionString"];
                if (string.IsNullOrWhiteSpace(connection))
                {
                    throw new InvalidOperationException(
                        "Database:PostgreSqlConnectionString is required when PostgreSQL is selected.");
                }

                options.UseNpgsql(connection);
                return;
            }

            if (!provider.Equals("Sqlite", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Unsupported database provider '{provider}'. Use Sqlite or PostgreSql.");
            }

            var sqlite = configuration["Database:SqliteConnectionString"]
                         ?? "Data Source=state/magic-control.db";
            EnsureSqliteDirectory(sqlite);
            options.UseSqlite(sqlite);
        }

        services.AddDbContextFactory<MagicControlDbContext>(Configure);
        return services;
    }

    private static void EnsureSqliteDirectory(string connectionString)
    {
        var builder = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(connectionString);
        if (string.IsNullOrWhiteSpace(builder.DataSource)
            || builder.DataSource.Equals(":memory:", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var fullPath = Path.GetFullPath(builder.DataSource);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }
}
