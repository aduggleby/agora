using System.Collections.Concurrent;

namespace Agora.Application.Utilities;

/// <summary>
/// In-process async mutex per string key (one entry per draft while it is being checked). Register as a singleton;
/// entries are dropped again when the last holder releases them, so idle keys cost nothing.
/// </summary>
public sealed class KeyedAsyncLock
{
    private sealed class Entry
    {
        public readonly SemaphoreSlim Semaphore = new(1, 1);
        public int Waiters;
    }

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public async Task<IDisposable> LockAsync(string key, CancellationToken cancellationToken)
    {
        Entry entry;
        lock (_gate)
        {
            entry = _entries.GetOrAdd(key, static _ => new Entry());
            entry.Waiters++;
        }

        try
        {
            await entry.Semaphore.WaitAsync(cancellationToken);
        }
        catch
        {
            Release(key, entry, held: false);
            throw;
        }

        return new Releaser(this, key, entry);
    }

    private void Release(string key, Entry entry, bool held)
    {
        lock (_gate)
        {
            if (held)
            {
                entry.Semaphore.Release();
            }

            entry.Waiters--;
            if (entry.Waiters == 0)
            {
                _entries.TryRemove(key, out _);
            }
        }
    }

    private sealed class Releaser(KeyedAsyncLock owner, string key, Entry entry) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                owner.Release(key, entry, held: true);
            }
        }
    }
}
