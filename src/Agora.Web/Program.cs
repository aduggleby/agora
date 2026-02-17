using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Web.Background;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<AgoraOptions>(builder.Configuration.GetSection(AgoraOptions.Section));
builder.Services.Configure<EmailSenderOptions>(builder.Configuration.GetSection(EmailSenderOptions.Section));

builder.Host.UseSerilog((context, services, loggerConfig) => loggerConfig
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

builder.Services.AddDbContext<AgoraDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=agora.db"));

builder.Services.AddScoped<ShareManager>();
builder.Services.AddHttpClient<IEmailSender, ResendEmailSender>();
builder.Services.AddHostedService<ExpiredShareCleanupService>();

builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 1024L * 1024 * 1024;
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
    db.Database.EnsureCreated();
}

app.MapGet("/", () => Results.Content("""
<!doctype html>
<html>
<head><meta charset='utf-8'/><title>Agora Upload</title></head>
<body style="font-family:sans-serif;max-width:900px;margin:2rem auto;">
<h1>Create Share</h1>
<form action="/api/shares" method="post" enctype="multipart/form-data">
<label>Uploader Email <input type="email" name="uploaderEmail" required /></label><br/><br/>
<label>Message <br/><textarea name="message" rows="4" cols="80"></textarea></label><br/><br/>
<label>Custom Zip Filename <input name="zipFileName" /></label><br/><br/>
<label>Expiry Mode
<select name="expiryMode"><option value="date">date</option><option value="indefinite">indefinite</option></select>
</label>
<label>Expires At (UTC) <input type="datetime-local" name="expiresAtUtc" /></label><br/><br/>
<label>Notify Mode
<select name="notifyMode"><option value="none">none</option><option value="once">once</option><option value="every_time">every_time</option></select>
</label><br/><br/>
<label>Template Mode
<select name="templateMode"><option value="account_default">account_default</option><option value="per_upload">per_upload</option></select>
</label><br/><br/>
<label>Title <input name="template.title" /></label><br/>
<label>H1 <input name="template.h1" /></label><br/>
<label>Description <input name="template.description" style="width:500px" /></label><br/>
<label>Background Image URL <input name="template.backgroundImageUrl" style="width:500px" /></label><br/><br/>
<label>Files <input type="file" name="files" multiple required /></label><br/><br/>
<button type="submit">Create Share</button>
</form>
</body></html>
""", "text/html"));

app.MapPut("/api/account/template", async (ShareManager manager, HttpRequest request, CancellationToken ct) =>
{
    var dto = await request.ReadFromJsonAsync<AccountTemplateDto>(cancellationToken: ct);
    if (dto is null || string.IsNullOrWhiteSpace(dto.UploaderEmail))
    {
        return Results.BadRequest("uploaderEmail is required");
    }

    await manager.UpsertAccountTemplateAsync(dto.UploaderEmail, new ShareTemplateData(
        string.IsNullOrWhiteSpace(dto.Title) ? "Shared file" : dto.Title,
        string.IsNullOrWhiteSpace(dto.H1) ? "A file was shared with you" : dto.H1,
        string.IsNullOrWhiteSpace(dto.Description) ? "Use the button below to download your file." : dto.Description,
        dto.BackgroundImageUrl), ct);

    return Results.NoContent();
});

app.MapPost("/api/shares", async (ShareManager manager, IOptions<AgoraOptions> options, HttpRequest request, CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest("Expected multipart/form-data");
    }

    var form = await request.ReadFormAsync(ct);
    var uploaderEmail = form["uploaderEmail"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(uploaderEmail))
    {
        return Results.BadRequest("uploaderEmail is required");
    }

    var files = form.Files;
    if (files.Count < 1)
    {
        return Results.BadRequest("At least one file is required");
    }

    var cfg = options.Value;
    if (files.Count > cfg.MaxFilesPerShare)
    {
        return Results.BadRequest($"Too many files. Max {cfg.MaxFilesPerShare}");
    }

    long total = 0;
    foreach (var file in files)
    {
        if (file.Length > cfg.MaxFileSizeBytes)
        {
            return Results.BadRequest($"File '{file.FileName}' exceeds max size");
        }

        total += file.Length;
    }

    if (total > cfg.MaxTotalUploadBytes)
    {
        return Results.BadRequest("Total upload size exceeds limit");
    }

    var expiryModeRaw = form["expiryMode"].ToString();
    var expiryMode = string.Equals(expiryModeRaw, "indefinite", StringComparison.OrdinalIgnoreCase)
        ? ExpiryMode.Indefinite
        : ExpiryMode.Date;

    DateTime? expiresAtUtc = null;
    if (expiryMode == ExpiryMode.Date)
    {
        var value = form["expiresAtUtc"].ToString();
        if (!DateTime.TryParse(value, out var parsed))
        {
            return Results.BadRequest("expiresAtUtc is required for date mode");
        }

        expiresAtUtc = DateTime.SpecifyKind(parsed, DateTimeKind.Local).ToUniversalTime();
        if (expiresAtUtc <= DateTime.UtcNow)
        {
            return Results.BadRequest("expiresAtUtc must be in the future");
        }
    }

    var notifyMode = form["notifyMode"].ToString().Trim().ToLowerInvariant();
    if (notifyMode is not ("none" or "once" or "every_time"))
    {
        return Results.BadRequest("notifyMode must be none|once|every_time");
    }

    var templateModeRaw = form["templateMode"].ToString();
    var templateMode = string.Equals(templateModeRaw, "per_upload", StringComparison.OrdinalIgnoreCase)
        ? TemplateMode.PerUpload
        : TemplateMode.AccountDefault;

    var tempRoot = Path.Combine(cfg.StorageRoot, "uploads", "tmp", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(tempRoot);

    var uploadFiles = new List<UploadSourceFile>(files.Count);

    try
    {
        foreach (var file in files)
        {
            var safeOriginalName = ArchiveNameResolver.Sanitize(file.FileName);
            var tempPath = Path.Combine(tempRoot, $"{Guid.NewGuid():N}-{safeOriginalName}");

            await using var outStream = File.Create(tempPath);
            await file.CopyToAsync(outStream, ct);

            uploadFiles.Add(new UploadSourceFile(
                TempPath: tempPath,
                OriginalFileName: safeOriginalName,
                OriginalSizeBytes: file.Length,
                ContentType: string.IsNullOrWhiteSpace(file.ContentType) ? "application/octet-stream" : file.ContentType));
        }

        var command = new CreateShareCommand
        {
            UploaderEmail = uploaderEmail,
            Message = form["message"].ToString(),
            ZipFileName = form["zipFileName"].ToString(),
            ExpiryMode = expiryMode,
            ExpiresAtUtc = expiresAtUtc,
            NotifyMode = notifyMode,
            TemplateMode = templateMode,
            TemplateTitle = form["template.title"].ToString(),
            TemplateH1 = form["template.h1"].ToString(),
            TemplateDescription = form["template.description"].ToString(),
            TemplateBackgroundImageUrl = form["template.backgroundImageUrl"].ToString(),
            Files = uploadFiles
        };

        var result = await manager.CreateShareAsync(command, ct);
        var shareUrl = $"{request.Scheme}://{request.Host}/s/{result.Token}";

        return Results.Created($"/api/shares/{result.Token}", new
        {
            result.ShareId,
            ShareUrl = shareUrl,
            result.ZipDisplayName,
            result.ExpiresAtUtc
        });
    }
    finally
    {
        if (Directory.Exists(tempRoot))
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }
});

app.MapGet("/api/shares/{token}", async (ShareManager manager, string token, CancellationToken ct) =>
{
    var share = await manager.FindByTokenAsync(token, ct);
    if (share is null)
    {
        return Results.NotFound();
    }

    if (ShareManager.IsExpired(share, DateTime.UtcNow))
    {
        return Results.StatusCode(StatusCodes.Status410Gone);
    }

    return Results.Ok(new
    {
        share.ZipDisplayName,
        share.ZipSizeBytes,
        FileCount = share.Files.Count,
        UploaderMessage = share.UploaderMessage,
        Page = new
        {
            Title = share.PageTitle,
            H1 = share.PageH1,
            Description = share.PageDescription,
            share.BackgroundImageUrl
        },
        share.ExpiresAtUtc,
        IsExpired = false
    });
});

app.MapGet("/s/{token}", async (ShareManager manager, string token, HttpRequest request, CancellationToken ct) =>
{
    var share = await manager.FindByTokenAsync(token, ct);
    if (share is null)
    {
        return Results.NotFound("Share not found.");
    }

    if (ShareManager.IsExpired(share, DateTime.UtcNow))
    {
        return Results.StatusCode(StatusCodes.Status410Gone);
    }

    var messageHtml = string.IsNullOrWhiteSpace(share.UploaderMessage)
        ? string.Empty
        : $"<p><strong>Message:</strong> {System.Net.WebUtility.HtmlEncode(share.UploaderMessage)}</p>";

    var bgStyle = string.IsNullOrWhiteSpace(share.BackgroundImageUrl)
        ? ""
        : $"background-image:url('{System.Net.WebUtility.HtmlEncode(share.BackgroundImageUrl)}');background-size:cover;";

    var html = $"""
<!doctype html>
<html>
<head><meta charset='utf-8'/><title>{System.Net.WebUtility.HtmlEncode(share.PageTitle)}</title></head>
<body style="font-family:sans-serif;max-width:900px;margin:2rem auto;{bgStyle}">
  <div style="background:#fff;padding:1.5rem;border-radius:12px;">
    <h1>{System.Net.WebUtility.HtmlEncode(share.PageH1)}</h1>
    <p>{System.Net.WebUtility.HtmlEncode(share.PageDescription)}</p>
    <p><strong>Archive:</strong> {System.Net.WebUtility.HtmlEncode(share.ZipDisplayName)} ({share.ZipSizeBytes} bytes)</p>
    <p><strong>Files:</strong> {share.Files.Count}</p>
    {messageHtml}
    <a href="/s/{token}/download">Download</a>
  </div>
</body>
</html>
""";

    return Results.Content(html, "text/html");
});

app.MapGet("/s/{token}/download", async (ShareManager manager, IOptions<AgoraOptions> options, string token, HttpRequest request, CancellationToken ct) =>
{
    var share = await manager.FindByTokenAsync(token, ct);
    if (share is null)
    {
        return Results.NotFound();
    }

    if (ShareManager.IsExpired(share, DateTime.UtcNow))
    {
        return Results.StatusCode(StatusCodes.Status410Gone);
    }

    var absolutePath = Path.Combine(options.Value.StorageRoot, share.ZipDiskPath);
    if (!File.Exists(absolutePath))
    {
        return Results.StatusCode(StatusCodes.Status410Gone);
    }

    var ip = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var userAgent = request.Headers.UserAgent.ToString();
    await manager.RecordDownloadAsync(share, token, ip, userAgent, ct);

    var stream = File.OpenRead(absolutePath);
    return Results.File(stream, "application/zip", share.ZipDisplayName);
});

app.Run();

public sealed record AccountTemplateDto(
    string UploaderEmail,
    string? Title,
    string? H1,
    string? Description,
    string? BackgroundImageUrl);
