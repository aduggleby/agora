using System.Security.Claims;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Web.Hangfire;
using Hangfire;
using Hangfire.Dashboard;
using Hangfire.InMemory;
using Hangfire.SqlServer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<AgoraOptions>(builder.Configuration.GetSection(AgoraOptions.Section));
builder.Services.Configure<EmailSenderOptions>(builder.Configuration.GetSection(EmailSenderOptions.Section));
builder.Services.Configure<FileSystemEmailOptions>(builder.Configuration.GetSection(FileSystemEmailOptions.Section));

builder.Host.UseSerilog((context, services, loggerConfig) => loggerConfig
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

var connectionString = builder.Configuration.GetConnectionString("Default") ?? "Data Source=agora.db";
var useSqlServer = connectionString.Contains("Server=", StringComparison.OrdinalIgnoreCase);

builder.Services.AddDbContext<AgoraDbContext>(options =>
{
    if (useSqlServer)
    {
        options.UseSqlServer(connectionString);
    }
    else
    {
        options.UseSqlite(connectionString);
    }
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/login";
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin"));
});

builder.Services.AddHangfire(configuration =>
{
    configuration.UseSimpleAssemblyNameTypeSerializer().UseRecommendedSerializerSettings();
    if (useSqlServer)
    {
        configuration.UseSqlServerStorage(connectionString, new SqlServerStorageOptions
        {
            PrepareSchemaIfNecessary = true
        });
    }
    else
    {
        configuration.UseInMemoryStorage();
    }
});

builder.Services.AddHangfireServer();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<ShareManager>();
builder.Services.AddScoped<EmailNotificationJob>();

var emailProvider = (builder.Configuration["Email:Provider"] ?? "resend").Trim().ToLowerInvariant();
if (emailProvider == "filesystem")
{
    builder.Services.AddSingleton<IEmailSender, FileSystemEmailSender>();
}
else
{
    builder.Services.AddHttpClient<IEmailSender, ResendEmailSender>();
}

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

using (var scope = app.Services.CreateScope())
{
    var recurringJobs = scope.ServiceProvider.GetRequiredService<IRecurringJobManager>();
    recurringJobs.AddOrUpdate<ShareManager>(
        "cleanup-expired-shares",
        service => service.CleanupExpiredSharesAsync(CancellationToken.None),
        "*/30 * * * *");
}

app.UseAuthentication();
app.UseAuthorization();

app.MapHangfireDashboard("/hangfire", new DashboardOptions
{
    Authorization = new IDashboardAuthorizationFilter[] { new AdminDashboardAuthorizationFilter() }
}).RequireAuthorization("AdminOnly");

app.MapGet("/login", async (HttpContext httpContext, AuthService authService, AgoraDbContext db, CancellationToken ct) =>
{
    if (httpContext.User.Identity?.IsAuthenticated == true)
    {
        return Results.Redirect("/");
    }

    var userCount = await db.Users.CountAsync(ct);
    var allowRegistration = await authService.GetAllowRegistrationAsync(ct);
    var msg = httpContext.Request.Query["msg"].ToString();

    var registerLink = userCount == 0 || allowRegistration
        ? "<p>No account yet? <a href=\"/register\">Register here</a>.</p>"
        : "<p>Registration is currently disabled.</p>";

    var body = $"""
<h1>Sign in</h1>
<form method=\"post\" action=\"/login\">
  <label>Email <input type=\"email\" name=\"email\" required /></label><br/><br/>
  <label>Password <input type=\"password\" name=\"password\" required /></label><br/><br/>
  <button type=\"submit\">Sign in</button>
</form>
{registerLink}
""";

    return Results.Content(RenderLayout("Login", null, body, msg), "text/html");
});

app.MapPost("/login", async (HttpContext httpContext, AuthService authService, CancellationToken ct) =>
{
    var form = await httpContext.Request.ReadFormAsync(ct);
    var email = form["email"].ToString();
    var password = form["password"].ToString();

    var result = await authService.LoginAsync(email, password, ct);
    if (!result.Success || result.User is null)
    {
        return Results.Redirect($"/login?msg={Uri.EscapeDataString(result.Error)}");
    }

    await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CreatePrincipal(result.User));
    return Results.Redirect("/");
});

app.MapPost("/logout", async (HttpContext httpContext) =>
{
    await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login?msg=Signed%20out");
}).RequireAuthorization();

app.MapGet("/register", async (HttpContext httpContext, AuthService authService, AgoraDbContext db, CancellationToken ct) =>
{
    if (httpContext.User.Identity?.IsAuthenticated == true)
    {
        return Results.Redirect("/");
    }

    var userCount = await db.Users.CountAsync(ct);
    var allowRegistration = await authService.GetAllowRegistrationAsync(ct);
    if (userCount > 0 && !allowRegistration)
    {
        return Results.Content(RenderLayout("Register", null, "<h1>Registration disabled</h1><p>Ask an administrator to enable registrations.</p>", "Registration disabled"), "text/html");
    }

    var msg = httpContext.Request.Query["msg"].ToString();
    var body = """
<h1>Create account</h1>
<form method="post" action="/register">
  <label>Email <input type="email" name="email" required /></label><br/><br/>
  <label>Password <input type="password" name="password" required /></label><br/><br/>
  <button type="submit">Register</button>
</form>
<p><a href="/login">Back to login</a></p>
""";

    return Results.Content(RenderLayout("Register", null, body, msg), "text/html");
});

app.MapPost("/register", async (HttpContext httpContext, AuthService authService, CancellationToken ct) =>
{
    var form = await httpContext.Request.ReadFormAsync(ct);
    var email = form["email"].ToString();
    var password = form["password"].ToString();

    var result = await authService.RegisterAsync(email, password, ct);
    if (!result.Success || result.User is null)
    {
        return Results.Redirect($"/register?msg={Uri.EscapeDataString(result.Error)}");
    }

    await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CreatePrincipal(result.User));
    return Results.Redirect("/");
});

app.MapGet("/", async (HttpContext httpContext, AuthService authService, CancellationToken ct) =>
{
    if (httpContext.User.Identity?.IsAuthenticated != true)
    {
        return Results.Redirect("/login");
    }

    var email = httpContext.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    var isAdmin = httpContext.User.IsInRole("admin");
    var msg = httpContext.Request.Query["msg"].ToString();
    var allowRegistration = isAdmin ? await authService.GetAllowRegistrationAsync(ct) : false;

    var adminPanel = isAdmin
        ? $"<details style=\"margin-bottom:1rem;\"><summary>Admin</summary><p>Registration is currently <strong>{(allowRegistration ? "enabled" : "disabled")}</strong>. <a href=\"/admin\">Manage users</a> | <a href=\"/hangfire\">Hangfire</a></p></details>"
        : string.Empty;

    var body = $"""
<h1>Create Share</h1>
{adminPanel}
<form action=\"/api/shares\" method=\"post\" enctype=\"multipart/form-data\">
<label>Message <br/><textarea name=\"message\" rows=\"4\" cols=\"80\"></textarea></label><br/><br/>
<label>Custom Zip Filename <input name=\"zipFileName\" /></label><br/><br/>
<label>Expiry Mode
<select name=\"expiryMode\"><option value=\"date\">date</option><option value=\"indefinite\">indefinite</option></select>
</label>
<label>Expires At (UTC) <input type=\"datetime-local\" name=\"expiresAtUtc\" /></label><br/><br/>
<label>Notify Mode
<select name=\"notifyMode\"><option value=\"none\">none</option><option value=\"once\">once</option><option value=\"every_time\">every_time</option></select>
</label><br/><br/>
<label>Template Mode
<select name=\"templateMode\"><option value=\"account_default\">account_default</option><option value=\"per_upload\">per_upload</option></select>
</label><br/><br/>
<label>Title <input name=\"template.title\" /></label><br/>
<label>H1 <input name=\"template.h1\" /></label><br/>
<label>Description <input name=\"template.description\" style=\"width:500px\" /></label><br/>
<label>Background Image URL <input name=\"template.backgroundImageUrl\" style=\"width:500px\" /></label><br/><br/>
<label>Files <input type=\"file\" name=\"files\" multiple required /></label><br/><br/>
<button type=\"submit\">Create Share</button>
</form>

<hr/>
<h2>Update default template</h2>
<form action=\"/api/account/template\" method=\"post\">
<label>Title <input name=\"title\" /></label><br/>
<label>H1 <input name=\"h1\" /></label><br/>
<label>Description <input name=\"description\" style=\"width:500px\" /></label><br/>
<label>Background Image URL <input name=\"backgroundImageUrl\" style=\"width:500px\" /></label><br/><br/>
<button type=\"submit\">Save template</button>
</form>
""";

    return Results.Content(RenderLayout("Agora", email, body, msg, isAdmin), "text/html");
}).RequireAuthorization();

app.MapGet("/admin", async (HttpContext httpContext, AuthService authService, CancellationToken ct) =>
{
    var currentUserEmail = httpContext.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    var users = await authService.GetUsersAsync(ct);
    var allowRegistration = await authService.GetAllowRegistrationAsync(ct);
    var msg = httpContext.Request.Query["msg"].ToString();

    var rows = string.Join("", users.Select(user =>
    {
        var id = user.Id.ToString();
        var roleSelect = $"<form method=\"post\" action=\"/admin/users/{id}/role\"><select name=\"role\"><option value=\"user\" {(user.Role == "user" ? "selected" : "")}>user</option><option value=\"admin\" {(user.Role == "admin" ? "selected" : "")}>admin</option></select><button type=\"submit\">Change</button></form>";
        var toggle = $"<form method=\"post\" action=\"/admin/users/{id}/enabled\"><input type=\"hidden\" name=\"enabled\" value=\"{(!user.IsEnabled).ToString().ToLowerInvariant()}\" /><button type=\"submit\">{(user.IsEnabled ? "Disable" : "Enable")}</button></form>";
        var delete = user.Email == currentUserEmail
            ? "(current user)"
            : $"<form method=\"post\" action=\"/admin/users/{id}/delete\" onsubmit=\"return confirm('Delete user?');\"><button type=\"submit\">Delete</button></form>";

        return $"<tr><td>{Html(user.Email)}</td><td>{Html(user.Role)}</td><td>{user.IsEnabled}</td><td>{roleSelect}</td><td>{toggle}</td><td>{delete}</td></tr>";
    }));

    var body = $"""
<h1>Admin</h1>
<p>Manage users, registration policy, and background jobs.</p>
<p><a href=\"/hangfire\">Open Hangfire Dashboard</a></p>

<h2>Registration policy</h2>
<form method=\"post\" action=\"/admin/settings/registration\">
  <input type=\"hidden\" name=\"enabled\" value=\"{(!allowRegistration).ToString().ToLowerInvariant()}\" />
  <button type=\"submit\">{(allowRegistration ? "Disable" : "Enable")} new user registration</button>
</form>

<h2>Users</h2>
<table border=\"1\" cellpadding=\"6\" cellspacing=\"0\">
<thead><tr><th>Email</th><th>Role</th><th>Enabled</th><th>Role</th><th>Status</th><th>Delete</th></tr></thead>
<tbody>{rows}</tbody>
</table>
""";

    return Results.Content(RenderLayout("Admin", currentUserEmail, body, msg, true), "text/html");
}).RequireAuthorization("AdminOnly");

app.MapPost("/admin/users/{id:guid}/role", async (Guid id, HttpRequest request, AuthService authService, CancellationToken ct) =>
{
    var form = await request.ReadFormAsync(ct);
    var role = form["role"].ToString();
    var ok = await authService.UpdateRoleAsync(id, role, ct);
    return Results.Redirect(ok ? "/admin?msg=Role%20updated" : "/admin?msg=Unable%20to%20update%20role");
}).RequireAuthorization("AdminOnly");

app.MapPost("/admin/users/{id:guid}/enabled", async (Guid id, HttpRequest request, AuthService authService, CancellationToken ct) =>
{
    var form = await request.ReadFormAsync(ct);
    var enabled = bool.TryParse(form["enabled"].ToString(), out var parsed) && parsed;
    var ok = await authService.SetEnabledAsync(id, enabled, ct);
    return Results.Redirect(ok ? "/admin?msg=User%20status%20updated" : "/admin?msg=Unable%20to%20update%20user");
}).RequireAuthorization("AdminOnly");

app.MapPost("/admin/users/{id:guid}/delete", async (Guid id, AuthService authService, CancellationToken ct) =>
{
    var ok = await authService.DeleteUserAsync(id, ct);
    return Results.Redirect(ok ? "/admin?msg=User%20deleted" : "/admin?msg=Unable%20to%20delete%20user");
}).RequireAuthorization("AdminOnly");

app.MapPost("/admin/settings/registration", async (HttpRequest request, AuthService authService, CancellationToken ct) =>
{
    var form = await request.ReadFormAsync(ct);
    var enabled = bool.TryParse(form["enabled"].ToString(), out var parsed) && parsed;
    await authService.SetAllowRegistrationAsync(enabled, ct);
    return Results.Redirect($"/admin?msg={(enabled ? "Registration%20enabled" : "Registration%20disabled")}");
}).RequireAuthorization("AdminOnly");

app.MapPost("/api/account/template", async (HttpContext context, ShareManager manager, HttpRequest request, CancellationToken ct) =>
{
    var form = await request.ReadFormAsync(ct);
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Unauthorized();
    }

    await manager.UpsertAccountTemplateAsync(email, new ShareTemplateData(
        string.IsNullOrWhiteSpace(form["title"].ToString()) ? "Shared file" : form["title"].ToString(),
        string.IsNullOrWhiteSpace(form["h1"].ToString()) ? "A file was shared with you" : form["h1"].ToString(),
        string.IsNullOrWhiteSpace(form["description"].ToString()) ? "Use the button below to download your file." : form["description"].ToString(),
        form["backgroundImageUrl"].ToString()), ct);

    return Results.Redirect("/?msg=Template%20saved");
}).RequireAuthorization();

app.MapPost("/api/shares", async (HttpContext context, ShareManager manager, IOptions<AgoraOptions> options, HttpRequest request, CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest("Expected multipart/form-data");
    }

    var uploaderEmail = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(uploaderEmail))
    {
        return Results.Unauthorized();
    }

    var form = await request.ReadFormAsync(ct);
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
        return Results.Redirect($"/?msg={Uri.EscapeDataString($"Share created: {shareUrl}")}");
    }
    finally
    {
        if (Directory.Exists(tempRoot))
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }
}).RequireAuthorization();

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

app.MapGet("/s/{token}", async (ShareManager manager, string token, CancellationToken ct) =>
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
        : $"<p><strong>Message:</strong> {Html(share.UploaderMessage)}</p>";

    var bgStyle = string.IsNullOrWhiteSpace(share.BackgroundImageUrl)
        ? ""
        : $"background-image:url('{Html(share.BackgroundImageUrl)}');background-size:cover;";

    var html = $"""
<!doctype html>
<html>
<head><meta charset='utf-8'/><title>{Html(share.PageTitle)}</title></head>
<body style="font-family:sans-serif;max-width:900px;margin:2rem auto;{bgStyle}">
  <div style="background:#fff;padding:1.5rem;border-radius:12px;">
    <h1>{Html(share.PageH1)}</h1>
    <p>{Html(share.PageDescription)}</p>
    <p><strong>Archive:</strong> {Html(share.ZipDisplayName)} ({share.ZipSizeBytes} bytes)</p>
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

static ClaimsPrincipal CreatePrincipal(UserAccount user)
{
    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new(ClaimTypes.Email, user.Email),
        new(ClaimTypes.Name, user.Email),
        new(ClaimTypes.Role, user.Role)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    return new ClaimsPrincipal(identity);
}

static string RenderLayout(string title, string? email, string body, string? message = null, bool isAdmin = false)
{
    var safeTitle = Html(title);
    var safeMessage = string.IsNullOrWhiteSpace(message) ? string.Empty : $"<p style=\"padding:0.5rem;background:#f6f7ff;border:1px solid #dfe3ff;\">{Html(message)}</p>";
    var authBlock = string.IsNullOrWhiteSpace(email)
        ? string.Empty
        : $"<div style=\"display:flex;gap:1rem;align-items:center;\"><span>Signed in as <strong>{Html(email)}</strong></span>{(isAdmin ? "<details><summary>Admin</summary><a href='/admin'>User Admin</a><br/><a href='/hangfire'>Hangfire</a></details>" : string.Empty)}<form method='post' action='/logout' style='display:inline;'><button type='submit'>Sign out</button></form></div>";

    return $"""
<!doctype html>
<html>
<head><meta charset='utf-8'/><title>{safeTitle}</title></head>
<body style="font-family:sans-serif;max-width:1000px;margin:1.5rem auto;padding:0 1rem;">
<header style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
  <a href="/" style="text-decoration:none;font-weight:700;">Agora</a>
  {authBlock}
</header>
{safeMessage}
{body}
</body>
</html>
""";
}

static string Html(string? value)
{
    return System.Net.WebUtility.HtmlEncode(value ?? string.Empty);
}
