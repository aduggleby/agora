using System.Text;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Services;
using Agora.Web.Endpoints;
using Agora.Web.Services;

namespace Agora.Web.Agents;

/// <summary>A file given inline in a call: exactly one of <see cref="Text"/> (UTF-8) and <see cref="ContentBase64"/>.</summary>
public sealed record InlineFile(string? FileName, string? Text = null, string? ContentBase64 = null);

/// <summary>A file in a draft, as the agent API reports it.</summary>
public sealed record StagedFileInfo(string DraftId, string FileId, string FileName, long SizeBytes);

/// <summary>Staging for the agent interface: inline decode and the checks shared with the browser staging routes.</summary>
public static class AgentStaging
{
    public const int MaxFileNameLength = 255;

    public static string PurposeToStorage(string? purpose) => string.Equals(purpose, AgentTicketStore.PurposeBackground, StringComparison.OrdinalIgnoreCase)
        ? ShareManager.UploadPurposeTemplateBackground
        : ShareManager.UploadPurposeShareFile;

    /// <summary>Null (file) or "background" are the purposes; anything else is a 400.</summary>
    public static bool IsValidPurpose(string? purpose) =>
        string.IsNullOrWhiteSpace(purpose) ||
        string.Equals(purpose, AgentTicketStore.PurposeFile, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(purpose, AgentTicketStore.PurposeBackground, StringComparison.OrdinalIgnoreCase);

    public static AgentResult<string> CheckFileName(string? fileName)
    {
        var name = fileName?.Trim();
        if (string.IsNullOrEmpty(name))
        {
            return AgentResult<string>.BadRequest("fileName is required.");
        }

        return name.Length > MaxFileNameLength
            ? AgentResult<string>.BadRequest($"fileName must be at most {MaxFileNameLength} characters.")
            : AgentResult<string>.Ok(name);
    }

    /// <summary>
    /// Decodes inline files (checking the combined decoded size against <see cref="AgentLimits.InlineMaxBytes"/>
    /// before decoding anything large). Null entries and entries with both or neither content field are 400.
    /// </summary>
    public static AgentResult<IReadOnlyList<(string Name, byte[] Bytes)>> DecodeInline(IReadOnlyList<InlineFile>? files)
    {
        if (files is null || files.Count == 0)
        {
            return AgentResult<IReadOnlyList<(string, byte[])>>.BadRequest("At least one file is required.");
        }

        long declared = 0;
        foreach (var file in files)
        {
            if (file is null || (file.Text is null) == (file.ContentBase64 is null))
            {
                return AgentResult<IReadOnlyList<(string, byte[])>>.BadRequest("Each file needs exactly one of text and contentBase64.");
            }

            declared += file.Text is { } text ? Encoding.UTF8.GetByteCount(text) : file.ContentBase64!.Length / 4L * 3;
        }

        if (declared > AgentLimits.InlineMaxBytes + 3 * files.Count)
        {
            return TooLargeInline<IReadOnlyList<(string, byte[])>>();
        }

        var decoded = new List<(string, byte[])>(files.Count);
        long total = 0;
        foreach (var file in files)
        {
            var name = CheckFileName(file.FileName);
            if (!name.IsOk)
            {
                return name.Refusal<IReadOnlyList<(string, byte[])>>();
            }

            byte[] bytes;
            if (file.Text is { } text)
            {
                bytes = Encoding.UTF8.GetBytes(text);
            }
            else
            {
                try
                {
                    bytes = Convert.FromBase64String(file.ContentBase64!);
                }
                catch (FormatException)
                {
                    return AgentResult<IReadOnlyList<(string, byte[])>>.BadRequest($"contentBase64 of '{name.Value}' is not valid base64.");
                }
            }

            total += bytes.Length;
            if (bytes.Length == 0)
            {
                return AgentResult<IReadOnlyList<(string, byte[])>>.BadRequest($"File '{name.Value}' is empty.");
            }

            decoded.Add((name.Value!, bytes));
        }

        return total > AgentLimits.InlineMaxBytes
            ? TooLargeInline<IReadOnlyList<(string, byte[])>>()
            : AgentResult<IReadOnlyList<(string, byte[])>>.Ok(decoded);
    }

    private static AgentResult<T> TooLargeInline<T>() => AgentResult<T>.Refuse(
        StatusCodes.Status413PayloadTooLarge,
        $"Inline files are limited to {AgentLimits.InlineMaxBytes} bytes in total per call. Ask for an upload URL for larger files.");

    /// <summary>
    /// How many bytes one more file of this purpose may add to the draft: the per-file limit, less when the draft is
    /// near the per-share total (share files) or the staging budget is low. A 413 (or the budget's own status) when
    /// nothing is left. Call after the caller's ownership of the draft was checked.
    /// </summary>
    public static async Task<AgentResult<long>> AllowanceAsync(
        ShareManager manager, AgoraOptions cfg, string draftId, string purpose, CancellationToken ct)
    {
        try
        {
            var allowance = purpose == ShareManager.UploadPurposeTemplateBackground
                ? cfg.MaxFileSizeBytes
                : UploadStagingEndpoints.ShareFileAllowance(manager, cfg, draftId);
            var budget = await manager.GetStageBudgetAsync(draftId, ct);
            return AgentResult<long>.Ok(Math.Min(allowance, budget.Remaining));
        }
        catch (UploadLimitException ex)
        {
            return AgentResult<long>.From(ex);
        }
    }

    /// <summary>The refusal for a file of <paramref name="sizeBytes"/> that does not fit the allowance, or null.</summary>
    public static async Task<AgentResult<long>?> CheckSizeAsync(
        ShareManager manager, AgoraOptions cfg, string draftId, string purpose, long sizeBytes, CancellationToken ct)
    {
        if (sizeBytes > cfg.MaxFileSizeBytes)
        {
            return AgentResult<long>.Refuse(StatusCodes.Status413PayloadTooLarge, UploadStagingEndpoints.TooLargeMessage);
        }

        var allowance = await AllowanceAsync(manager, cfg, draftId, purpose, ct);
        if (!allowance.IsOk)
        {
            return allowance;
        }

        return sizeBytes > allowance.Value
            ? AgentResult<long>.Refuse(StatusCodes.Status413PayloadTooLarge, UploadStagingEndpoints.TooLargeMessage)
            : null;
    }

    /// <summary>
    /// Stages one buffered, seekable stream into the draft (the draft was opened by the caller). Background images
    /// get the same type and pixel checks as the browser's background upload.
    /// </summary>
    public static async Task<AgentResult<StagedFileInfo>> StageAsync(
        ShareManager manager,
        AgoraOptions cfg,
        Guid ownerUserId,
        string draftId,
        string fileName,
        Stream source,
        string purpose,
        CancellationToken ct)
    {
        var sizeBytes = source.Length;
        if (sizeBytes > cfg.MaxFileSizeBytes)
        {
            return AgentResult<StagedFileInfo>.BadRequest($"File '{fileName}' exceeds max size.");
        }

        if (purpose == ShareManager.UploadPurposeTemplateBackground)
        {
            if (!ContentTypePolicy.IsAllowedBackgroundImage(fileName))
            {
                return AgentResult<StagedFileInfo>.BadRequest("Only JPG, PNG, or WEBP files are allowed.");
            }

            source.Position = 0;
            if (!OgImageGenerator.IsAcceptableBackground(source))
            {
                return AgentResult<StagedFileInfo>.BadRequest(OgImageGenerator.BackgroundRefusalMessage);
            }

            source.Position = 0;
        }

        try
        {
            var staged = await manager.StageUploadAsync(ownerUserId, draftId, fileName, sizeBytes, source, ct, purpose);
            return AgentResult<StagedFileInfo>.Ok(new StagedFileInfo(draftId, staged.UploadId, staged.OriginalFileName, staged.OriginalSizeBytes), StatusCodes.Status201Created);
        }
        catch (InvalidOperationException ex)
        {
            return AgentResult<StagedFileInfo>.BadRequest(ex.Message);
        }
        catch (UploadLimitException ex)
        {
            return AgentResult<StagedFileInfo>.From(ex);
        }
    }
}
