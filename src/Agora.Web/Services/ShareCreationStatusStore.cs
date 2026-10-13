using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Agora.Application.Models;
using Microsoft.Extensions.Options;

namespace Agora.Web.Services;

public sealed class ShareCreationStatusStore(IOptions<AgoraOptions> options)
{
    private readonly string _root = Path.Combine(options.Value.StorageRoot, "uploads", "share-create-status");
    private static readonly Step[] DefaultSteps =
    [
        new("validate", "Validate request", "pending", null, null),
        new("create_share", "Create share archive", "pending", null, null),
        new("queue_previews", "Queue preview generation", "pending", null, null),
        new("notify_uploader", "Notify uploader by email", "pending", null, null)
    ];

    public sealed record Entry(
        string Token,
        string UploaderEmail,
        string State,
        string? Error,
        string? JobId,
        IReadOnlyList<Step> Steps,
        DateTime CreatedAtUtc,
        DateTime UpdatedAtUtc);

    public sealed record Step(
        string Key,
        string Label,
        string State,
        string? Detail,
        DateTime? UpdatedAtUtc);

    public Entry MarkQueued(string token, string uploaderEmail, string? jobId)
    {
        var now = DateTime.UtcNow;
        var entry = new Entry(
            Token: token,
            UploaderEmail: uploaderEmail.Trim(),
            State: "queued",
            Error: null,
            JobId: jobId,
            Steps: DefaultSteps,
            CreatedAtUtc: now,
            UpdatedAtUtc: now);

        Write(entry);
        return entry;
    }

    public Entry MarkProcessing(string token)
    {
        var existing = Read(token);
        var now = DateTime.UtcNow;
        var entry = new Entry(
            Token: token,
            UploaderEmail: existing?.UploaderEmail ?? string.Empty,
            State: "processing",
            Error: null,
            JobId: existing?.JobId,
            Steps: existing?.Steps ?? DefaultSteps,
            CreatedAtUtc: existing?.CreatedAtUtc ?? now,
            UpdatedAtUtc: now);
        Write(entry);
        return entry;
    }

    public Entry MarkCompleted(string token)
    {
        var existing = Read(token);
        var now = DateTime.UtcNow;
        var entry = new Entry(
            Token: token,
            UploaderEmail: existing?.UploaderEmail ?? string.Empty,
            State: "completed",
            Error: null,
            JobId: existing?.JobId,
            Steps: (existing?.Steps ?? DefaultSteps)
                .Select(step => step with { State = "completed", Detail = step.Detail, UpdatedAtUtc = now })
                .ToList(),
            CreatedAtUtc: existing?.CreatedAtUtc ?? now,
            UpdatedAtUtc: now);
        Write(entry);
        return entry;
    }

    public Entry MarkFailed(string token, string error)
    {
        var existing = Read(token);
        var now = DateTime.UtcNow;
        var message = string.IsNullOrWhiteSpace(error) ? "Share creation failed." : error.Trim();
        var steps = (existing?.Steps ?? DefaultSteps).ToList();
        var activeIndex = steps.FindIndex(step => string.Equals(step.State, "active", StringComparison.OrdinalIgnoreCase));
        if (activeIndex >= 0)
        {
            steps[activeIndex] = steps[activeIndex] with
            {
                State = "failed",
                Detail = message,
                UpdatedAtUtc = now
            };
        }
        var entry = new Entry(
            Token: token,
            UploaderEmail: existing?.UploaderEmail ?? string.Empty,
            State: "failed",
            Error: message,
            JobId: existing?.JobId,
            Steps: steps,
            CreatedAtUtc: existing?.CreatedAtUtc ?? now,
            UpdatedAtUtc: now);
        Write(entry);
        return entry;
    }

    public Entry UpdateStep(string token, string stepKey, string stepState, string? detail = null)
    {
        var existing = Read(token);
        var now = DateTime.UtcNow;
        var steps = (existing?.Steps ?? DefaultSteps).ToList();
        var index = steps.FindIndex(step => string.Equals(step.Key, stepKey, StringComparison.Ordinal));
        if (index >= 0)
        {
            steps[index] = steps[index] with
            {
                State = stepState,
                Detail = detail,
                UpdatedAtUtc = now
            };
        }

        var entry = new Entry(
            Token: token,
            UploaderEmail: existing?.UploaderEmail ?? string.Empty,
            State: existing?.State ?? "processing",
            Error: existing?.Error,
            JobId: existing?.JobId,
            Steps: steps,
            CreatedAtUtc: existing?.CreatedAtUtc ?? now,
            UpdatedAtUtc: now);
        Write(entry);
        return entry;
    }

    public Entry? Read(string token)
    {
        var path = GetPath(token);
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<Entry>(json);
        }
        catch
        {
            return null;
        }
    }

    private void Write(Entry entry)
    {
        Directory.CreateDirectory(_root);
        var path = GetPath(entry.Token);
        var json = JsonSerializer.Serialize(entry);
        File.WriteAllText(path, json);
    }

    private string GetPath(string token)
    {
        var normalized = (token ?? string.Empty).Trim();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized))).ToLowerInvariant();
        return Path.Combine(_root, $"{hash}.json");
    }
}
