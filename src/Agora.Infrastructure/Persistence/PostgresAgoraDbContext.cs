using Microsoft.EntityFrameworkCore;

namespace Agora.Infrastructure.Persistence;

/// <summary>
/// PostgreSQL flavour of <see cref="AgoraDbContext"/>. Exists only so PostgreSQL gets its own migration set
/// (Migrations/Postgres) and model snapshot: EF Core matches migrations to a context by exact type, so the
/// SQL Server and PostgreSQL migrations never mix. Application code keeps depending on <see cref="AgoraDbContext"/>.
/// </summary>
public sealed class PostgresAgoraDbContext(DbContextOptions<PostgresAgoraDbContext> options) : AgoraDbContext(options);
