using Microsoft.Extensions.Caching.Memory;

namespace Agora.Infrastructure.Auth;

/// <summary>
/// Sign-in lockout per (account, client IP): after <see cref="MaxFailures"/> wrong passwords for one account from one
/// address within <see cref="Window"/>, that address is refused for that account for <see cref="Duration"/>, while
/// other addresses with the correct password still sign in. State lives in process memory, so it is per instance
/// (a single running instance is assumed) and resets on restart.
/// </summary>
public sealed class LoginLockouts(IMemoryCache cache, TimeProvider? timeProvider = null)
{
    public const int MaxFailures = 5;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan Duration = TimeSpan.FromMinutes(15);

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    private sealed class Bucket
    {
        public int Failures;
        public DateTimeOffset? LockedUntil;
    }

    public bool IsLockedOut(Guid userId, string clientIp)
    {
        if (!cache.TryGetValue(Key(userId, clientIp), out Bucket? bucket) || bucket is null)
        {
            return false;
        }

        lock (bucket)
        {
            return bucket.LockedUntil is { } until && until > _time.GetUtcNow();
        }
    }

    public void RecordFailure(Guid userId, string clientIp)
    {
        var key = Key(userId, clientIp);
        var bucket = cache.GetOrCreate(key, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = Window;
            return new Bucket();
        })!;

        lock (bucket)
        {
            bucket.Failures += 1;
            if (bucket.Failures >= MaxFailures && bucket.LockedUntil is null)
            {
                bucket.LockedUntil = _time.GetUtcNow().Add(Duration);
                cache.Set(key, bucket, Duration);
            }
        }
    }

    public void Reset(Guid userId, string clientIp) => cache.Remove(Key(userId, clientIp));

    private static string Key(Guid userId, string clientIp)
    {
        var ip = (clientIp ?? string.Empty).Trim().ToLowerInvariant();
        return $"login-lockout:{userId:N}:{(ip.Length == 0 ? "unknown" : ip)}";
    }
}
