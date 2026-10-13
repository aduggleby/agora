using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Agora.Infrastructure.Persistence;

// Design-time factories used by `dotnet ef` so each provider's context can be created without starting the app
// and independent of Database:Provider. Use scripts/add-migration.sh <Name> to add a migration to both sets.
// `migrations add` never connects. For commands that do (e.g. `database update`), set
// ConnectionStrings__Default to a connection string for the matching provider.

/// <summary>
/// Design-time factory for the SQL Server context (<see cref="AgoraDbContext"/>).
/// </summary>
public sealed class SqlServerDesignTimeDbContextFactory : IDesignTimeDbContextFactory<AgoraDbContext>
{
    public AgoraDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__Default")
            ?? "Server=localhost;Database=agora;Trusted_Connection=True;TrustServerCertificate=True";
        return new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlServer(connectionString).Options);
    }
}

/// <summary>
/// Design-time factory for the PostgreSQL context (<see cref="PostgresAgoraDbContext"/>).
/// </summary>
public sealed class PostgresDesignTimeDbContextFactory : IDesignTimeDbContextFactory<PostgresAgoraDbContext>
{
    public PostgresAgoraDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__Default")
            ?? "Host=localhost;Database=agora;Username=postgres";
        return new PostgresAgoraDbContext(new DbContextOptionsBuilder<PostgresAgoraDbContext>().UseNpgsql(connectionString).Options);
    }
}
