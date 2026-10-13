using Hangfire;
using Hangfire.PostgreSql;
using Hangfire.PostgreSql.Factories;
using Hangfire.SqlServer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Agora.Infrastructure.Persistence;

/// <summary>
/// Supported database providers (<c>Database:Provider</c>, env <c>Database__Provider</c>).
/// </summary>
public enum DatabaseProvider
{
    /// <summary>Microsoft SQL Server (default; existing installs are unchanged).</summary>
    SqlServer,

    /// <summary>PostgreSQL (Npgsql).</summary>
    Postgres,
}

/// <summary>
/// Registers the configured database provider for EF Core and Hangfire.
/// One connection string (<c>ConnectionStrings:Default</c>) is used for both.
/// </summary>
public static class DatabaseSetup
{
    /// <summary>Configuration key for the provider switch.</summary>
    public const string ProviderKey = "Database:Provider";

    /// <summary>
    /// Parses the provider value. Missing/empty means <see cref="DatabaseProvider.SqlServer"/>;
    /// <c>SqlServer</c> and <c>Postgres</c> are accepted case-insensitively.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown for any other value.</exception>
    public static DatabaseProvider ParseProvider(string? value)
    {
        var raw = value?.Trim();
        if (string.IsNullOrEmpty(raw) || string.Equals(raw, "SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            return DatabaseProvider.SqlServer;
        }

        if (string.Equals(raw, "Postgres", StringComparison.OrdinalIgnoreCase))
        {
            return DatabaseProvider.Postgres;
        }

        throw new InvalidOperationException(
            $"Unsupported database provider '{raw}' in {ProviderKey} (env Database__Provider). Use 'SqlServer' (default) or 'Postgres'.");
    }

    /// <summary>
    /// Registers <see cref="AgoraDbContext"/>. For Postgres the implementation is <see cref="PostgresAgoraDbContext"/>,
    /// so the PostgreSQL migration set is used while application code keeps depending on <see cref="AgoraDbContext"/>.
    /// </summary>
    public static IServiceCollection AddAgoraDbContext(this IServiceCollection services, DatabaseProvider provider, string connectionString)
    {
        return provider switch
        {
            DatabaseProvider.SqlServer => services.AddDbContext<AgoraDbContext>(options => options.UseSqlServer(connectionString)),
            DatabaseProvider.Postgres => services.AddDbContext<AgoraDbContext, PostgresAgoraDbContext>(options => options.UseNpgsql(connectionString)),
            _ => throw new ArgumentOutOfRangeException(nameof(provider), provider, "Unsupported database provider.")
        };
    }

    /// <summary>
    /// Configures Hangfire job storage for the configured provider (co-located with the app database).
    /// </summary>
    public static IGlobalConfiguration UseAgoraHangfireStorage(this IGlobalConfiguration configuration, DatabaseProvider provider, string connectionString)
    {
        return provider switch
        {
            DatabaseProvider.SqlServer => configuration.UseSqlServerStorage(connectionString, new SqlServerStorageOptions
            {
                PrepareSchemaIfNecessary = true
            }),
            DatabaseProvider.Postgres => configuration.UseStorage(CreatePostgreSqlStorage(connectionString)),
            _ => throw new ArgumentOutOfRangeException(nameof(provider), provider, "Unsupported database provider.")
        };
    }

    /// <summary>
    /// Creates Hangfire PostgreSQL storage (schema <c>hangfire</c>, created/upgraded on startup).
    /// Sliding invisibility keeps long jobs (zip builds, previews) from being re-queued after a fixed timeout.
    /// </summary>
    public static PostgreSqlStorage CreatePostgreSqlStorage(string connectionString)
    {
        var options = new PostgreSqlStorageOptions
        {
            PrepareSchemaIfNecessary = true,
            InvisibilityTimeout = TimeSpan.FromMinutes(5),
            UseSlidingInvisibilityTimeout = true,
            QueuePollInterval = TimeSpan.FromSeconds(5),
        };
        return new PostgreSqlStorage(new NpgsqlConnectionFactory(connectionString, options), options);
    }
}
