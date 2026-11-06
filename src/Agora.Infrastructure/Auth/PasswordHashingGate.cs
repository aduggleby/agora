using Agora.Application.Utilities;

namespace Agora.Infrastructure.Auth;

/// <summary>
/// Process-wide ceiling on concurrent PBKDF2 work (password hashing and verification). Anonymous auth posts each cost
/// a 600,000-iteration hash, so without a ceiling a burst from many addresses can occupy every core. A caller that
/// cannot get a slot within <see cref="MaxWait"/> gets <see cref="PasswordHashingBusyException"/> (mapped to 503
/// with Retry-After). Registered once per process (singleton).
/// </summary>
public sealed class PasswordHashingGate : IDisposable
{
    public static readonly TimeSpan DefaultMaxWait = TimeSpan.FromSeconds(2);

    private readonly SemaphoreSlim _slots;

    /// <param name="maxConcurrent">Slots; 0 or less means <see cref="Environment.ProcessorCount"/>.</param>
    /// <param name="maxWait">How long a caller waits for a slot before giving up; default 2 seconds.</param>
    public PasswordHashingGate(int maxConcurrent = 0, TimeSpan? maxWait = null)
    {
        MaxConcurrent = maxConcurrent > 0 ? maxConcurrent : Math.Max(1, Environment.ProcessorCount);
        MaxWait = maxWait ?? DefaultMaxWait;
        _slots = new SemaphoreSlim(MaxConcurrent, MaxConcurrent);
    }

    public int MaxConcurrent { get; }

    public TimeSpan MaxWait { get; }

    public Task<string> HashAsync(string password, CancellationToken cancellationToken) =>
        RunAsync(() => PasswordHasher.Hash(password), cancellationToken);

    public Task<bool> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken) =>
        RunAsync(() => PasswordHasher.Verify(password, storedHash), cancellationToken);

    public async Task<T> RunAsync<T>(Func<T> work, CancellationToken cancellationToken)
    {
        if (!await _slots.WaitAsync(MaxWait, cancellationToken))
        {
            throw new PasswordHashingBusyException();
        }

        try
        {
            return work();
        }
        finally
        {
            _slots.Release();
        }
    }

    public void Dispose() => _slots.Dispose();
}

/// <summary>Every password-hashing slot stayed busy for the gate's wait time; the caller should retry shortly.</summary>
public sealed class PasswordHashingBusyException() : Exception(BusyMessage)
{
    public const string BusyMessage = "The server is busy. Please try again in a few seconds.";
    public const int RetryAfterSeconds = 5;
}
