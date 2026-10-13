using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Agora.Infrastructure.Services;

/// <summary>
/// Bytes a request is about to write: <see cref="ScratchBytes"/> under the scratch area (staging, tmp) and
/// <see cref="DurableBytes"/> that land on the same volume only with the FileSystem store (originals and archive).
/// </summary>
public sealed record ScratchDemand(long ScratchBytes, long DurableBytes)
{
    public long TotalBytes => ScratchBytes + DurableBytes;

    public static ScratchDemand Scratch(long bytes) => new(Math.Max(0, bytes), 0);
}

/// <summary>
/// Global high-water mark for the local scratch area (staged uploads, drafts, share-create status, tmp) and free-space
/// floor of the StorageRoot volume. Register as a singleton. Admission counts the measured scratch size (a directory
/// walk, cached for <see cref="CacheDuration"/>), every outstanding <see cref="ScratchReservation"/> and the request's
/// own demand; a cache refresh replaces only the measured figure, never the reservations. Endpoints preflight with
/// <see cref="EnsureCanAdmit(ScratchDemand)"/> before reading a body; the code that actually writes holds a
/// reservation for the duration of the write, so nothing is charged twice. The volume's free space is read live.
/// </summary>
public sealed class ScratchSpaceMonitor
{
    public static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(30);

    private readonly AgoraOptions _options;
    private readonly StorageProvider _provider;
    private readonly Func<string, long> _availableFreeBytes;
    private readonly Func<string, long> _scratchBytes;
    private readonly TimeProvider _clock;
    private readonly ILogger<ScratchSpaceMonitor> _logger;
    private readonly object _gate = new();
    private long _cachedScratchBytes;
    private DateTimeOffset _cachedAtUtc = DateTimeOffset.MinValue;
    private long _reservedScratchBytes;
    private long _reservedDurableBytes;

    public ScratchSpaceMonitor(IOptions<AgoraOptions> options, StorageProvider provider, ILogger<ScratchSpaceMonitor> logger)
        : this(options.Value, provider, AvailableFreeBytes, MeasureScratchBytes, TimeProvider.System, logger)
    {
    }

    public ScratchSpaceMonitor(
        AgoraOptions options,
        StorageProvider provider,
        Func<string, long> availableFreeBytes,
        Func<string, long> scratchBytes,
        TimeProvider clock,
        ILogger<ScratchSpaceMonitor>? logger = null)
    {
        _options = options;
        _provider = provider;
        _availableFreeBytes = availableFreeBytes;
        _scratchBytes = scratchBytes;
        _clock = clock;
        _logger = logger ?? NullLogger<ScratchSpaceMonitor>.Instance;
    }

    /// <summary>Outstanding reservations, for diagnostics and tests.</summary>
    public (long ScratchBytes, long DurableBytes) Reserved
    {
        get
        {
            lock (_gate)
            {
                return (_reservedScratchBytes, _reservedDurableBytes);
            }
        }
    }

    /// <summary>
    /// What building a share from <paramref name="totalFileBytes"/> of originals writes: the scratch zip (plus an
    /// encrypted copy for password-protected shares) and, with the FileSystem store, the durable originals and archive
    /// on the same volume. In S3 mode only scratch is local.
    /// </summary>
    public ScratchDemand ArchiveDemand(long totalFileBytes, bool passwordProtected, long backgroundBytes = 0)
    {
        var files = Math.Max(0, totalFileBytes);
        var scratch = files + (passwordProtected ? files : 0);
        var durable = _provider == StorageProvider.FileSystem ? 2 * files + Math.Max(0, backgroundBytes) : 0;
        return new ScratchDemand(scratch, durable);
    }

    /// <summary>Bytes written to the durable store: on the StorageRoot volume with FileSystem, elsewhere with S3.</summary>
    public ScratchDemand DurableDemand(long bytes) =>
        new(0, _provider == StorageProvider.FileSystem ? Math.Max(0, bytes) : 0);

    /// <summary>Read-only preflight: throws 507 when the demand would not fit right now. Reserves nothing.</summary>
    public void EnsureCanAdmit(ScratchDemand demand)
    {
        lock (_gate)
        {
            CheckUnderLock(demand);
        }
    }

    public void EnsureCanAdmit(long scratchBytes) => EnsureCanAdmit(ScratchDemand.Scratch(scratchBytes));

    /// <summary>
    /// Admits the demand (or throws 507) and holds it against the budget until the returned reservation is disposed.
    /// Call <see cref="ScratchReservation.Commit"/> when the bytes stay in scratch after the write (staged uploads),
    /// so the budget keeps counting them until the next measurement.
    /// </summary>
    public ScratchReservation Reserve(ScratchDemand demand)
    {
        lock (_gate)
        {
            CheckUnderLock(demand);
            _reservedScratchBytes += demand.ScratchBytes;
            _reservedDurableBytes += demand.DurableBytes;
            return new ScratchReservation(this, demand);
        }
    }

    public ScratchReservation Reserve(long scratchBytes) => Reserve(ScratchDemand.Scratch(scratchBytes));

    internal void Release(ScratchDemand demand, bool committed)
    {
        lock (_gate)
        {
            _reservedScratchBytes = Math.Max(0, _reservedScratchBytes - demand.ScratchBytes);
            _reservedDurableBytes = Math.Max(0, _reservedDurableBytes - demand.DurableBytes);
            if (committed)
            {
                _cachedScratchBytes += demand.ScratchBytes;
            }
        }
    }

    private void CheckUnderLock(ScratchDemand demand)
    {
        var storageRoot = Path.GetFullPath(_options.StorageRoot);
        var limits = _options.Scratch;

        if (limits.MinFreeBytes > 0)
        {
            long free;
            try
            {
                free = _availableFreeBytes(storageRoot);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                // Unknown volume state: do not block uploads on a probe failure, but say so.
                _logger.LogWarning(ex, "Free-space probe for {StorageRoot} failed; Scratch:MinFreeBytes is not enforced for this request", storageRoot);
                free = long.MaxValue;
            }

            var outstanding = _reservedScratchBytes + _reservedDurableBytes;
            if (free - outstanding - demand.TotalBytes < limits.MinFreeBytes)
            {
                throw Insufficient();
            }
        }

        if (limits.MaxBytes <= 0)
        {
            return;
        }

        var now = _clock.GetUtcNow();
        if (now - _cachedAtUtc >= CacheDuration)
        {
            _cachedScratchBytes = _scratchBytes(storageRoot);
            _cachedAtUtc = now;
        }

        if (_cachedScratchBytes + _reservedScratchBytes + demand.ScratchBytes > limits.MaxBytes)
        {
            throw Insufficient();
        }
    }

    private static UploadLimitException Insufficient() => new(
        UploadLimitKind.InsufficientStorage,
        "The server is out of storage space for uploads right now. Please try again later.");

    private static long AvailableFreeBytes(string storageRoot)
    {
        Directory.CreateDirectory(storageRoot);
        return new DriveInfo(storageRoot).AvailableFreeSpace;
    }

    /// <summary>Sum of file sizes under the scratch directories (uploads/staged*, uploads/drafts, tmp, status).</summary>
    private static long MeasureScratchBytes(string storageRoot)
    {
        var roots = new[]
        {
            Path.Combine(storageRoot, "uploads", "staged"),
            Path.Combine(storageRoot, "uploads", "staged-template-backgrounds"),
            Path.Combine(storageRoot, "uploads", "drafts"),
            Path.Combine(storageRoot, "uploads", "share-create-status"),
            ScratchFiles.Root(storageRoot)
        };

        long total = 0;
        foreach (var root in roots)
        {
            if (!Directory.Exists(root))
            {
                continue;
            }

            var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
            foreach (var path in Directory.EnumerateFiles(root, "*", options))
            {
                try
                {
                    total += new FileInfo(path).Length;
                }
                catch (IOException)
                {
                    // Deleted between enumeration and stat.
                }
            }
        }

        return total;
    }
}

/// <summary>Outstanding scratch demand; dispose when the write is over, after <see cref="Commit"/> if the bytes stay.</summary>
public sealed class ScratchReservation(ScratchSpaceMonitor owner, ScratchDemand demand) : IDisposable
{
    private int _released;
    private bool _committed;

    public ScratchDemand Demand { get; } = demand;

    public void Commit() => _committed = true;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _released, 1) == 0)
        {
            owner.Release(Demand, _committed);
        }
    }
}
