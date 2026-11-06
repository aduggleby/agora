using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;

namespace Agora.Web.Endpoints;

/// <summary>
/// Counts the upload requests in flight (from admission until the response is disposed) per key, so one client cannot
/// hold many long-lived scratch reservations at once. Keys are a client address (public uploads), an account (signed-in
/// uploads) and a draft. Acquisition is all-or-nothing across the keys of one request.
/// </summary>
public sealed class UploadConcurrency
{
    /// <summary>In-flight upload requests allowed per key.</summary>
    public const int MaxInFlightPerKey = 2;

    /// <summary>
    /// Minimum body rate for upload requests: 32 KiB/s (256 kbit/s, below any connection that can usefully send
    /// gigabytes) after a 60 s grace. Kestrel's default (240 B/s) lets a trickling request keep its scratch
    /// reservation for days; at this rate the largest single reservation (one file of 5 GiB by default) is held
    /// for at most about 45 hours, and every client gets only <see cref="MaxInFlightPerKey"/> of them.
    /// </summary>
    public static readonly MinDataRate UploadMinBodyDataRate = new(bytesPerSecond: 32 * 1024, gracePeriod: TimeSpan.FromSeconds(60));

    public const string RefusalMessage = "Too many uploads are running at the same time. Wait for one to finish and try again.";

    private readonly Dictionary<string, int> _inFlight = new(StringComparer.Ordinal);

    /// <summary>A lease on every key, or null (nothing held) when any of them is already at the cap.</summary>
    public IDisposable? TryAcquire(params string[] keys)
    {
        lock (_inFlight)
        {
            if (keys.Any(key => _inFlight.GetValueOrDefault(key) >= MaxInFlightPerKey))
            {
                return null;
            }

            foreach (var key in keys)
            {
                _inFlight[key] = _inFlight.GetValueOrDefault(key) + 1;
            }
        }

        return new Lease(this, keys);
    }

    /// <summary>The current count of a key (tests).</summary>
    public int InFlight(string key)
    {
        lock (_inFlight)
        {
            return _inFlight.GetValueOrDefault(key);
        }
    }

    public static string AddressKey(string clientAddress) => $"addr:{clientAddress}";

    public static string AccountKey(Guid userId) => $"user:{userId:N}";

    public static string DraftKey(string draftShareId) => $"draft:{draftShareId}";

    /// <summary>
    /// Acquires the keys for this request and ties the lease to the response; false (with nothing held) when a key is
    /// at its cap, so the caller answers 429 before reading the body.
    /// </summary>
    public bool TryAdmit(HttpContext context, params string[] keys)
    {
        var lease = TryAcquire(keys);
        if (lease is null)
        {
            return false;
        }

        context.Response.RegisterForDispose(lease);
        return true;
    }

    public static IResult TooManyJson() =>
        Results.Json(new { error = RefusalMessage }, statusCode: StatusCodes.Status429TooManyRequests);

    /// <summary>
    /// Raises the minimum body data rate for this request (HTTP/1.x only; HTTP/2 and test servers have no per-request
    /// setting, where the server-wide default applies).
    /// </summary>
    public static void ApplyMinBodyDataRate(HttpContext context)
    {
        if (context.Features.Get<IHttpMinRequestBodyDataRateFeature>() is not { } feature)
        {
            return;
        }

        try
        {
            feature.MinDataRate = UploadMinBodyDataRate;
        }
        catch (NotSupportedException)
        {
            // HTTP/2 and HTTP/3 connections do not support a per-request rate.
        }
    }

    private void Release(string[] keys)
    {
        lock (_inFlight)
        {
            foreach (var key in keys)
            {
                var next = _inFlight.GetValueOrDefault(key) - 1;
                if (next <= 0)
                {
                    _inFlight.Remove(key);
                }
                else
                {
                    _inFlight[key] = next;
                }
            }
        }
    }

    private sealed class Lease(UploadConcurrency owner, string[] keys) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                owner.Release(keys);
            }
        }
    }
}
