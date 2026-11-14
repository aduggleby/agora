using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Microsoft.Extensions.Options;

namespace Agora.Web.Agents;

/// <summary>
/// One-time upload and download URLs. A ticket is 32 random bytes (base64url); only its SHA-256 is stored, as
/// <c>{StorageRoot}/uploads/agent-tickets/{hash}.json</c>, so a copy of the directory grants nothing. A ticket can be
/// read without being used (<see cref="Peek"/>) so cheap refusals do not burn it, and is used by an atomic rename
/// (<see cref="TryClaim"/>): of any number of concurrent callers exactly one wins.
/// </summary>
public sealed class AgentTicketStore(IOptions<AgoraOptions> options, TimeProvider? clock = null)
{
    public const string KindUpload = "upload";
    public const string KindDownload = "download";
    public const string PurposeFile = "file";
    public const string PurposeBackground = "background";

    /// <summary>
    /// What a ticket authorizes. Upload: stage <see cref="FileName"/> (exactly <see cref="SizeBytes"/> bytes) into
    /// <see cref="DraftId"/>. Download: read <see cref="FileId"/> of the share <see cref="ShareToken"/>.
    /// <see cref="UploadCode"/> is set on anonymous (upload link) tickets only; owner tickets carry the
    /// <see cref="TokenId"/> that issued them and stop working when that token does.
    /// </summary>
    public sealed record Ticket(
        string Kind,
        Guid OwnerUserId,
        DateTime ExpiresAtUtc,
        string? DraftId = null,
        string? UploadCode = null,
        string? Purpose = null,
        string? FileName = null,
        long SizeBytes = 0,
        string? ShareToken = null,
        Guid? FileId = null,
        Guid? TokenId = null)
    {
        public bool IsPublic => UploadCode is not null;
    }

    private const string ClaimedMarker = ".claimed-";
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private readonly string _root = Path.Combine(options.Value.StorageRoot, "uploads", "agent-tickets");
    private long _lastSweepTicks;

    public DateTime UtcNow => _clock.GetUtcNow().UtcDateTime;

    /// <summary>Stores the ticket and returns its plaintext, shown to the caller once.</summary>
    public string Issue(Ticket ticket)
    {
        SweepIfDue();
        var plain = TokenCodec.GenerateToken();
        Directory.CreateDirectory(_root);
        var path = PathFor(plain);
        var temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        File.WriteAllText(temp, JsonSerializer.Serialize(ticket));
        File.Move(temp, path);
        return plain;
    }

    /// <summary>The ticket when it is known, unexpired and unused; null otherwise. Does not use it up.</summary>
    public Ticket? Peek(string plain) => IsWellFormed(plain) ? Read(PathFor(plain)) : null;

    /// <summary>
    /// Uses the ticket up: an atomic rename claims it for exactly one caller. Null when unknown, expired or already
    /// claimed. The claimed file is removed at once.
    /// </summary>
    public Ticket? TryClaim(string plain)
    {
        if (!IsWellFormed(plain))
        {
            return null;
        }

        var path = PathFor(plain);
        var claimed = path + ClaimedMarker + Guid.NewGuid().ToString("N");
        try
        {
            File.Move(path, claimed);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException or IOException)
        {
            return null;
        }

        var ticket = Read(claimed);
        ScratchFiles.TryDelete(claimed);
        return ticket;
    }

    /// <summary>Removes expired tickets and claimed leftovers; returns how many files went.</summary>
    public int Sweep()
    {
        if (!Directory.Exists(_root))
        {
            return 0;
        }

        var removed = 0;
        foreach (var path in Directory.EnumerateFiles(_root))
        {
            try
            {
                // Claimed and half-written files are leftovers of a crash once they are a minute old; the rest is a
                // ticket, removed when it expired (or cannot be read).
                var leftover = path.Contains(ClaimedMarker, StringComparison.Ordinal) || path.Contains(".tmp-", StringComparison.Ordinal);
                var stale = leftover
                    ? File.GetLastWriteTimeUtc(path) <= DateTime.UtcNow.AddMinutes(-1)
                    : Read(path) is null;
                if (stale)
                {
                    File.Delete(path);
                    removed++;
                }
            }
            catch (IOException)
            {
            }
        }

        return removed;
    }

    private void SweepIfDue()
    {
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref _lastSweepTicks);
        if (now - last >= 60_000 && Interlocked.CompareExchange(ref _lastSweepTicks, now, last) == last)
        {
            Sweep();
        }
    }

    private Ticket? Read(string path)
    {
        try
        {
            var ticket = JsonSerializer.Deserialize<Ticket>(File.ReadAllText(path));
            return ticket is not null && ticket.ExpiresAtUtc > UtcNow ? ticket : null;
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    // 32 bytes as base64url is exactly 43 characters; anything else never reaches the file system.
    private static bool IsWellFormed(string? plain) =>
        plain is { Length: 43 } && plain.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    private string PathFor(string plain) => Path.Combine(_root, TokenCodec.HashToken(plain) + ".json");
}
