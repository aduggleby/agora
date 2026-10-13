using System.Text;
using System.Security.Claims;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Logging;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Auth;
using Agora.Web.Endpoints;
using Agora.Web.Hubs;
using Agora.Web.Services;
using Agora.Web.Hangfire;
using Agora.Web.Startup;
using Hangfire.Console;
using Hangfire;
using Hangfire.Dashboard;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Serilog;
using System.Data;
using System.Net.Mail;
using System.Security.Cryptography;

// Composes the web host, infrastructure services, middleware pipeline, and startup data/bootstrap routines.
var builder = WebApplication.CreateBuilder(args);
var storageRootPath = Path.GetFullPath(builder.Configuration[$"{AgoraOptions.Section}:StorageRoot"] ?? new AgoraOptions().StorageRoot);

// Multipart bodies above 64 KB are buffered to ASPNETCORE_TEMP (default: the system temp dir, which may be a small
// tmpfs in hardened containers). Point it under StorageRoot unless set explicitly. Must happen before the first request is processed.
if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASPNETCORE_TEMP")))
{
    Environment.SetEnvironmentVariable("ASPNETCORE_TEMP", Directory.CreateDirectory(Path.Combine(storageRootPath, "tmp", "aspnet")).FullName);
}

var initialUploadLimits = builder.Configuration.GetSection(AgoraOptions.Section);
var configuredMaxFileSizeBytes = initialUploadLimits.GetValue<long?>("MaxFileSizeBytes") ?? (5L * 1024 * 1024 * 1024);
var configuredMaxTotalUploadBytes = initialUploadLimits.GetValue<long?>("MaxTotalUploadBytes") ?? (10L * 1024 * 1024 * 1024);
var maxRequestBodySize = Math.Max(configuredMaxFileSizeBytes, configuredMaxTotalUploadBytes);
// One stage request carries one file; cap its body at that file size plus multipart overhead so a single request can
// never buffer more than one file's worth into tmp/aspnet.
var stageRequestBodyLimit = configuredMaxFileSizeBytes + 1024 * 1024;
// Anonymous submissions carry only form fields (file ids, sender details), never a file.
const long createRequestBodyLimit = 1024 * 1024;
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = maxRequestBodySize;
});

builder.Services.Configure<AgoraOptions>(builder.Configuration.GetSection(AgoraOptions.Section));
builder.Services.Configure<EmailSenderOptions>(builder.Configuration.GetSection(EmailSenderOptions.Section));
builder.Services.Configure<FileSystemEmailOptions>(builder.Configuration.GetSection(FileSystemEmailOptions.Section));

// Logging: always stdout; plus a daily rolling file (Agora:Logging:File:Enabled/Path/RetainedDays).
// Sinks are configured here; the Serilog config section still supplies MinimumLevel/overrides/enrichers.
var logFile = LogFileOptions.Resolve(builder.Configuration);
builder.Host.UseSerilog((context, services, loggerConfig) =>
{
    const string outputTemplate = "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}";
    loggerConfig
        .ReadFrom.Configuration(WithoutSerilogSinks(context.Configuration))
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .Enrich.With(new TokenRedactionEnricher())
        .WriteTo.Console(outputTemplate: outputTemplate);
    if (logFile.Enabled)
    {
        loggerConfig.WriteTo.File(
            Path.Combine(logFile.Path, LogFileOptions.FileNamePattern),
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: logFile.RetainedDays,
            shared: true,
            flushToDiskInterval: TimeSpan.FromSeconds(2),
            outputTemplate: outputTemplate);
    }
});

var connectionString = builder.Configuration.GetConnectionString("Default");
if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException("Connection string 'Default' is not configured (env ConnectionStrings__Default).");
}

// Throws for unsupported values so a typo can never silently fall back to the wrong database.
var databaseProvider = DatabaseSetup.ParseProvider(builder.Configuration[DatabaseSetup.ProviderKey]);
builder.Services.AddAgoraDbContext(databaseProvider, connectionString);
var healthChecks = builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("database", tags: [DatabaseHealthCheck.ReadyTag], timeout: TimeSpan.FromSeconds(5));

// Durable content (share files, archives, backgrounds, previews): Storage:Provider=FileSystem (default, rooted at
// StorageRoot) or S3. Scratch (staging, drafts, tmp/, preview locks) always stays under StorageRoot.
var storageProvider = builder.Services.AddAgoraObjectStore(builder.Configuration, storageRootPath);
if (storageProvider == StorageProvider.S3)
{
    builder.Services.TryAddSingleton(TimeProvider.System);
    builder.Services.AddSingleton<ObjectStoreHealthCheck>();
    healthChecks.AddCheck<ObjectStoreHealthCheck>("object-store", tags: [DatabaseHealthCheck.ReadyTag], timeout: TimeSpan.FromSeconds(5));
}

// Persist DataProtection keys so auth cookies and gate tokens survive restarts.
var dataProtectionKeysPath = builder.Configuration["DataProtection:KeysPath"];
if (string.IsNullOrWhiteSpace(dataProtectionKeysPath))
{
    dataProtectionKeysPath = Path.Combine(Path.GetDirectoryName(storageRootPath) ?? storageRootPath, "keys");
}

builder.Services.AddDataProtection()
    .SetApplicationName("Agora")
    .PersistKeysToFileSystem(Directory.CreateDirectory(dataProtectionKeysPath));

// Sign-in and CSRF cookies share one Secure policy (Agora:Auth:SecureCookies). Auto means Secure in Production,
// SameAsRequest elsewhere so Development and E2E keep working on http://localhost.
var authOptions = builder.Configuration.GetSection(AgoraOptions.Section).GetSection("Auth").Get<AgoraAuthOptions>() ?? new AgoraAuthOptions();
var cookieSecurePolicy = CookieSessions.SecurePolicy(authOptions, builder.Environment.IsProduction());
builder.Services.TryAddSingleton(TimeProvider.System);
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/login";
        options.ExpireTimeSpan = CookieSessions.SessionLifetime(authOptions);
        options.SlidingExpiration = true;
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = cookieSecurePolicy;
        options.Events.OnValidatePrincipal = CookieSessions.ValidatePrincipalAsync;
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin"));
});
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "agora.csrf";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = cookieSecurePolicy;
    options.FormFieldName = "__RequestVerificationToken";
    options.HeaderName = "X-CSRF-TOKEN";
});
// E2E mode (test endpoints, no login throttling) also requires ASPNETCORE_ENVIRONMENT=E2E, so a stray flag
// can never enable it in Production.
var isE2E = builder.Environment.IsEnvironment("E2E") &&
            (builder.Configuration.GetValue<bool>("E2E:Enabled") ||
             string.Equals(Environment.GetEnvironmentVariable("AGORA_E2E"), "1", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(Environment.GetEnvironmentVariable("AGORA_E2E"), "true", StringComparison.OrdinalIgnoreCase));
var rateLimits = builder.Configuration.GetSection(AgoraOptions.Section).GetSection("RateLimits").Get<AgoraRateLimitOptions>() ?? new AgoraRateLimitOptions();
builder.Services.AddRateLimiter(options => RateLimitSetup.Configure(options, rateLimits, isE2E));

var razorPages = builder.Services.AddRazorPages();
if (builder.Environment.IsDevelopment())
{
    razorPages.AddRazorRuntimeCompilation();
}

builder.Services.AddHangfire(configuration =>
{
    configuration.UseSimpleAssemblyNameTypeSerializer().UseRecommendedSerializerSettings().UseConsole();
    configuration.UseAgoraHangfireStorage(databaseProvider, connectionString);
});

builder.Services.AddHangfireServer(options =>
{
    options.Queues = ["default"];
});
builder.Services.AddHangfireServer(options =>
{
    // Keep preview generation isolated so long-running image work does not starve default jobs.
    options.Queues = ["previews"];
    options.WorkerCount = Math.Max(1, Environment.ProcessorCount / 4);
});
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<LoginLockouts>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<ShareManager>();
builder.Services.AddSingleton<KeyedAsyncLock>();
builder.Services.AddSingleton(sp => new ScratchSpaceMonitor(
    sp.GetRequiredService<IOptions<AgoraOptions>>(),
    storageProvider,
    sp.GetRequiredService<ILogger<ScratchSpaceMonitor>>()));
builder.Services.AddSingleton<IShareContentStore, ShareContentStore>();
builder.Services.AddScoped<AuthEmailJob>();
builder.Services.AddScoped<EmailNotificationJob>();
builder.Services.AddScoped<QueuedShareCreationJob>();
builder.Services.AddScoped<SharePreviewJobService>();
builder.Services.AddSingleton<ShareCreationStatusStore>();
builder.Services.AddSingleton<ShareProgressBroadcaster>();
builder.Services.AddSingleton<SharePreviewImageGenerator>();
builder.Services.AddSignalR(options => options.AddFilter<SessionRevalidationHubFilter>());
builder.Services.AddHttpClient<IDownloaderGeoLookup, IpWhoIsDownloaderGeoLookup>(client =>
{
    client.BaseAddress = new Uri("https://ipwho.is/");
    client.Timeout = TimeSpan.FromSeconds(2);
});
builder.Services.AddScoped<IShareExperienceRenderer, ArchiveShareExperienceRenderer>();
builder.Services.AddScoped<IShareExperienceRenderer, GalleryShareExperienceRenderer>();
builder.Services.AddScoped<ShareExperienceRendererResolver>();
builder.Services.AddScoped<IEmailTemplateRenderer, RazorEmailTemplateRenderer>();
builder.Services.AddSingleton(new Agora.Web.Services.OgImageGenerator(
    System.IO.Path.Combine(builder.Environment.ContentRootPath, "Fonts")));

var emailProvider = (builder.Configuration["Email:Provider"] ?? "resend").Trim().ToLowerInvariant();
if (emailProvider == "filesystem")
{
    builder.Services.AddScoped<IEmailSender, FileSystemEmailSender>();
}
else
{
    builder.Services.AddHttpClient<IEmailSender, ResendEmailSender>();
}

builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = configuredMaxTotalUploadBytes;
});
// X-Forwarded-* headers are honoured only from loopback and the proxies listed in Agora:TrustedProxies; from any
// other peer they are ignored, so clients cannot pick their own RemoteIpAddress (every per-IP rate limiter and the
// download log key on it), scheme or host. The setup resets the known lists first, so ASPNETCORE_FORWARDEDHEADERS_ENABLED
// (whose startup filter clears them to trust everyone) cannot widen this.
var trustedProxies = TrustedProxies.Parse(builder.Configuration[TrustedProxies.Key]);
builder.Services.Configure<ForwardedHeadersOptions>(options => ForwardedHeadersSetup.Configure(options, trustedProxies));

// Links that leave the browser (emails, share links, OG tags) are built from Agora:PublicBaseUrl only. The request
// host is an acceptable stand-in solely for local Development and the E2E server, which have no fixed origin.
var allowRequestHostFallback = builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("E2E");
var publicBaseUrl = PublicBaseUrl.Resolve(builder.Configuration[PublicBaseUrl.Key], required: !allowRequestHostFallback);
builder.Services.AddSingleton(new PublicBaseUrlResolver(publicBaseUrl, allowRequestHostFallback));
builder.Services.AddSingleton<IPublicOriginProvider>(sp => sp.GetRequiredService<PublicBaseUrlResolver>());

var app = builder.Build();
app.Logger.LogInformation(
    "Database provider: {DatabaseProvider}. Storage provider: {StorageProvider}. File logging: {FileLogging} ({FileLoggingPath}, retention: {FileLoggingRetention}).",
    databaseProvider,
    storageProvider,
    logFile.Enabled,
    Path.GetFullPath(logFile.Path),
    logFile.RetainedDays is { } retainedDays ? $"{retainedDays} days" : "unlimited");
app.Logger.LogInformation(
    "Public base URL: {PublicBaseUrl}. Trusted proxies: {TrustedProxies} (plus loopback).",
    publicBaseUrl ?? "<request host>",
    trustedProxies.IsEmpty ? "<none>" : builder.Configuration[TrustedProxies.Key]);
if (trustedProxies.IsEmpty && !allowRequestHostFallback)
{
    app.Logger.LogWarning(
        "Agora__TrustedProxies is empty: X-Forwarded-For/Proto/Host from a reverse proxy are ignored. Behind a proxy, " +
        "list its address or network there; otherwise every client shares the proxy's IP, download logs record the proxy " +
        "and all anonymous traffic is throttled collectively at Agora__RateLimits__AnonymousPerMinute ({AnonymousPerMinute}/min).",
        rateLimits.AnonymousPerMinute);
}

var allowedHosts = (builder.Configuration["AllowedHosts"] ?? "*").Trim();
if (app.Environment.IsProduction() && (allowedHosts.Length == 0 || allowedHosts == "*"))
{
    app.Logger.LogWarning(
        "AllowedHosts is '*': requests for any Host header are served. Set it to the public hostname(s) in production " +
        "(for example AllowedHosts=files.example.com) and make sure the reverse proxy does not forward arbitrary Host values.");
}

var isDevelopment = app.Environment.IsDevelopment();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
    try
    {
        await db.Database.MigrateAsync();
        app.Logger.LogInformation("Applied EF Core migrations successfully.");
        var backfilled = await OwnerBackfill.RunAsync(db, CancellationToken.None);
        if (!backfilled.Skipped)
        {
            app.Logger.LogInformation(
                "Owner-id backfill completed: {ShareCount} share(s) and {TemplateCount} account template(s) stamped.",
                backfilled.Shares,
                backfilled.Templates);
        }

        if (backfilled.QuarantinedShares > 0 || backfilled.QuarantinedTemplates > 0)
        {
            app.Logger.LogWarning(
                "{ShareCount} share(s) and {TemplateCount} account template(s) have no owner and are reachable by nobody.",
                backfilled.QuarantinedShares,
                backfilled.QuarantinedTemplates);
        }
    }
    catch (Exception ex)
    {
        app.Logger.LogCritical(ex, "EF Core migration or owner backfill failed during startup. Stopping application.");
        throw;
    }
}

if (isDevelopment)
{
    using var scope = app.Services.CreateScope();
    var authService = scope.ServiceProvider.GetRequiredService<AuthService>();
    var result = await authService.EnsureDevelopmentUserAsync(CancellationToken.None);
    if (result.Created && !string.IsNullOrWhiteSpace(result.GeneratedPassword))
    {
        app.Logger.LogInformation(
            "Development user {Email} created with random password {Password}",
            result.User.Email,
            result.GeneratedPassword);
    }
}

using (var scope = app.Services.CreateScope())
{
    var recurringJobs = scope.ServiceProvider.GetRequiredService<IRecurringJobManager>();
    recurringJobs.AddOrUpdate<ShareManager>(
        "cleanup-expired-shares",
        service => service.CleanupExpiredSharesAsync(CancellationToken.None),
        "*/30 * * * *");
    recurringJobs.AddOrUpdate<ShareManager>(
        "cleanup-zombie-uploads",
        service => service.CleanupZombieUploadsAsync(CancellationToken.None),
        "*/15 * * * *");
}

app.UseForwardedHeaders();
app.UseAgoraSecurityHeaders();
if (!isDevelopment)
{
    app.UseAgoraExceptionHandler();
}

app.UseStaticFiles();
app.UseAuthentication();
app.UseAgoraCsrf(isE2E, cookieSecurePolicy, app.Logger);
app.UseRateLimiter();
app.UseAuthorization();
app.MapRazorPages();

// Health endpoints (anonymous, not rate limited). /ready returns 503 when the database is unreachable.
app.MapHealthChecks("/live", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous().DisableRateLimiting();
app.MapHealthChecks("/ready", new HealthCheckOptions { Predicate = c => c.Tags.Contains(DatabaseHealthCheck.ReadyTag) })
    .AllowAnonymous()
    .DisableRateLimiting();

app.MapHangfireDashboard("/hangfire", new DashboardOptions
{
    Authorization = new IDashboardAuthorizationFilter[] { new AdminDashboardAuthorizationFilter() }
}).RequireAuthorization("AdminOnly");


app.MapPost("/login", async (HttpContext httpContext, AuthService authService, IDataProtectionProvider dataProtectionProvider, CancellationToken ct) =>
{
    var form = await httpContext.Request.ReadFormAsync(ct);
    var email = form["email"].ToString();
    var password = form["password"].ToString();

    var result = await authService.LoginAsync(email, password, httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", ct);
    if (!result.Success || result.User is null)
    {
        if (string.Equals(result.Error, AuthService.EmailConfirmationRequiredError, StringComparison.Ordinal))
        {
            var gateToken = LoginEmailConfirmationGate.Create(dataProtectionProvider, email);
            return Results.Redirect($"/confirm-email-required?email={Uri.EscapeDataString(email)}&gate={Uri.EscapeDataString(gateToken)}");
        }

        return Results.Redirect($"/login?msg={Uri.EscapeDataString(result.Error)}");
    }

    await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CookieSessions.CreatePrincipal(result.User));
    return Results.Redirect("/");
}).RequireRateLimiting(RateLimitSetup.AuthEndpoints);

app.MapPost("/logout", async (HttpContext httpContext) =>
{
    await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login?msg=Signed%20out");
}).RequireAuthorization();

if (isDevelopment)
{
    app.MapPost("/login/development", async (HttpContext httpContext, AuthService authService, CancellationToken ct) =>
    {
        var result = await authService.EnsureDevelopmentUserAsync(ct);
        await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CookieSessions.CreatePrincipal(result.User));
        return Results.Redirect("/");
    }).RequireRateLimiting(RateLimitSetup.AuthEndpoints);
}


app.MapPost("/register", async (HttpContext httpContext, AuthService authService, PublicBaseUrlResolver publicBaseUrls, CancellationToken ct) =>
{
    var form = await httpContext.Request.ReadFormAsync(ct);
    var email = form["email"].ToString();
    var password = form["password"].ToString();
    var confirmUrlBase = $"{publicBaseUrls.Resolve(httpContext.Request)}/auth/confirm-email";

    var result = await authService.RegisterAsync(email, password, confirmUrlBase, ct);
    if (!result.Success)
    {
        return Results.Redirect($"/register?msg={Uri.EscapeDataString(result.Error)}");
    }

    return Results.Redirect("/login?msg=Check%20your%20email%20to%20confirm%20your%20account");
}).RequireRateLimiting(RateLimitSetup.AuthEndpoints);


app.MapPost("/auth/resend-confirmation", async (HttpContext httpContext, AuthService authService, PublicBaseUrlResolver publicBaseUrls, CancellationToken ct) =>
{
    if (!httpContext.Request.HasFormContentType)
    {
        return Results.Redirect("/login?msg=Please%20enter%20your%20email%20address");
    }

    var form = await httpContext.Request.ReadFormAsync(ct);
    var email = form["email"].ToString();
    var confirmUrlBase = $"{publicBaseUrls.Resolve(httpContext.Request)}/auth/confirm-email";

    await authService.ResendEmailConfirmationAsync(email, confirmUrlBase, ct);
    return Results.Redirect("/login?msg=If%20the%20account%20is%20unconfirmed%2C%20a%20confirmation%20email%20was%20sent");
}).RequireRateLimiting(RateLimitSetup.AuthEndpoints);

if (isE2E)
{
    app.MapPost("/api/e2e/users", async (AgoraDbContext db, HttpRequest request, CancellationToken ct) =>
    {
        if (!request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "Expected form data." });
        }

        var form = await request.ReadFormAsync(ct);
        var email = EmailAddress.Normalize(form["email"].ToString());
        var password = form["password"].ToString();
        var defaultNotifyMode = form["defaultNotifyMode"].ToString();
        var defaultExpiryMode = form["defaultExpiryMode"].ToString();
        var role = form["role"].ToString().Trim().ToLowerInvariant();
        if (role.Length == 0)
        {
            role = "user";
        }
        else if (role is not ("user" or "admin"))
        {
            return Results.BadRequest(new { error = "role must be 'user' or 'admin'." });
        }

        if (string.IsNullOrWhiteSpace(email))
        {
            email = $"e2e-{Guid.NewGuid():N}@example.test";
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            password = Convert.ToHexString(Guid.NewGuid().ToByteArray())[..16] + "aA!";
        }

        var exists = await db.Users.AnyAsync(x => x.Email == email, ct);
        if (exists)
        {
            return Results.Conflict(new { error = "User already exists." });
        }

        var uploadToken = TokenCodec.GenerateAlphanumericToken(8);
        for (var attempt = 0; attempt < 16; attempt += 1)
        {
            if (!await db.Users.AnyAsync(x => x.UploadToken == uploadToken, ct))
            {
                break;
            }

            uploadToken = TokenCodec.GenerateAlphanumericToken(8);
        }

        var userId = Guid.NewGuid();
        db.Users.Add(new UserAccount
        {
            Id = userId,
            Email = email,
            DisplayName = email.Contains('@', StringComparison.Ordinal) ? email[..email.IndexOf('@', StringComparison.Ordinal)] : email,
            EmailConfirmed = true,
            EmailConfirmedAtUtc = DateTime.UtcNow,
            PasswordHash = PasswordHasher.Hash(password),
            SecurityStamp = SecurityStamps.New(),
            Role = role,
            IsEnabled = true,
            CreatedAtUtc = DateTime.UtcNow,
            DefaultNotifyMode = string.IsNullOrWhiteSpace(defaultNotifyMode) ? "once" : defaultNotifyMode.Trim(),
            DefaultExpiryMode = string.IsNullOrWhiteSpace(defaultExpiryMode) ? "7_days" : defaultExpiryMode.Trim(),
            UploadToken = uploadToken,
            UploadTokenUpdatedAtUtc = DateTime.UtcNow
        });
        db.AccountTemplates.Add(new AccountTemplate
        {
            Id = Guid.NewGuid(),
            OwnerUserId = userId,
            UploaderEmail = email,
            Title = $"by {email}",
            H1 = "A file was shared with you",
            Description = string.Empty,
            UpdatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync(ct);

        return Results.Ok(new { email, password });
    });

    app.MapPost("/api/e2e/shares/{token}/expires-in-seconds", async (AgoraDbContext db, string token, HttpRequest request, CancellationToken ct) =>
    {
        if (!request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "Expected form data." });
        }

        var form = await request.ReadFormAsync(ct);
        var secondsRaw = form["seconds"].ToString();
        if (!int.TryParse(secondsRaw, out var seconds))
        {
            return Results.BadRequest(new { error = "seconds is required." });
        }

        var share = await db.Shares.SingleOrDefaultAsync(x => x.ShareToken == token, ct);
        if (share is null)
        {
            return Results.NotFound(new { error = "Share not found." });
        }

        share.ExpiresAtUtc = DateTime.UtcNow.AddSeconds(seconds);
        await db.SaveChangesAsync(ct);
        return Results.Ok(new { share.Id, share.ExpiresAtUtc });
    });

    app.MapPost("/api/e2e/users/regenerate-upload-token", async (AgoraDbContext db, HttpRequest request, CancellationToken ct) =>
    {
        if (!request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "Expected form data." });
        }

        var form = await request.ReadFormAsync(ct);
        var email = EmailAddress.Normalize(form["email"].ToString());
        if (string.IsNullOrWhiteSpace(email))
        {
            return Results.BadRequest(new { error = "email is required." });
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, ct);
        if (user is null)
        {
            return Results.NotFound(new { error = "User not found." });
        }

        var uploadToken = TokenCodec.GenerateAlphanumericToken(8);
        for (var attempt = 0; attempt < 16; attempt += 1)
        {
            if (!await db.Users.AnyAsync(x => x.UploadToken == uploadToken && x.Id != user.Id, ct))
            {
                break;
            }

            uploadToken = TokenCodec.GenerateAlphanumericToken(8);
        }

        user.UploadToken = uploadToken;
        user.UploadTokenUpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);

        return Results.Ok(new { user.Email, uploadToken });
    });

    app.MapPost("/api/e2e/shares/reserve-token", async (AgoraDbContext db, HttpRequest request, CancellationToken ct) =>
    {
        if (!request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "Expected form data." });
        }

        var form = await request.ReadFormAsync(ct);
        var token = form["token"].ToString().Trim();
        var uploaderEmail = EmailAddress.Normalize(form["uploaderEmail"].ToString());
        if (!IsValidShareToken(token))
        {
            return Results.BadRequest(new { error = "token must be 8-64 letters, numbers, hyphens, or underscores." });
        }

        if (string.IsNullOrWhiteSpace(uploaderEmail))
        {
            uploaderEmail = "e2e-reserved-token@example.test";
        }

        var exists = await db.Shares.AnyAsync(x => x.ShareToken == token, ct);
        if (exists)
        {
            return Results.Conflict(new { error = "Share token already exists." });
        }

        db.Shares.Add(new Share
        {
            Id = Guid.NewGuid(),
            UploaderEmail = uploaderEmail,
            ShareToken = token,
            ZipDisplayName = "reserved-token.zip",
            ZipDiskPath = "zips/e2e/reserved-token.zip",
            ZipSizeBytes = 0,
            ShareExperienceType = "archive",
            AccessMode = "download_only",
            NotifyMode = "none",
            CreatedAtUtc = DateTime.UtcNow,
            PageTitle = "Reserved share token",
            PageH1 = "Reserved share token",
            PageDescription = "Reserved for e2e collision tests.",
            PageContainerPosition = "center"
        });
        await db.SaveChangesAsync(ct);
        return Results.Ok(new { token, uploaderEmail });
    });
}


app.MapPost("/admin/users/{id:guid}/role", async (Guid id, HttpContext httpContext, HttpRequest request, AuthService authService, CancellationToken ct) =>
{
    var currentUserIdRaw = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (Guid.TryParse(currentUserIdRaw, out var currentUserId) && currentUserId == id)
    {
        return Results.Redirect("/admin?msg=You%20cannot%20change%20your%20own%20role");
    }

    var form = await request.ReadFormAsync(ct);
    var role = form["role"].ToString();
    var ok = await authService.UpdateRoleAsync(id, role, ct);
    return Results.Redirect(ok ? "/admin?msg=Role%20updated" : "/admin?msg=Unable%20to%20update%20role");
}).RequireAuthorization("AdminOnly");

app.MapPost("/api/admin/users/{id:guid}/role", async (Guid id, HttpContext httpContext, HttpRequest request, AuthService authService, CancellationToken ct) =>
{
    var currentUserIdRaw = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (Guid.TryParse(currentUserIdRaw, out var currentUserId) && currentUserId == id)
    {
        return Results.BadRequest(new { ok = false, message = "You cannot change your own role." });
    }

    var form = await request.ReadFormAsync(ct);
    var role = form["role"].ToString();
    var ok = await authService.UpdateRoleAsync(id, role, ct);
    return ok
        ? Results.Ok(new { ok = true })
        : Results.BadRequest(new { ok = false, message = "Unable to update role." });
}).RequireAuthorization("AdminOnly");

app.MapPost("/api/admin/users/{id:guid}/enabled", async (Guid id, HttpContext httpContext, HttpRequest request, AuthService authService, CancellationToken ct) =>
{
    var currentUserIdRaw = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    var form = await request.ReadFormAsync(ct);
    var enabled = FormValues.LastBool(form["enabled"]);

    if (Guid.TryParse(currentUserIdRaw, out var currentUserId) && currentUserId == id && !enabled)
    {
        return Results.BadRequest(new { ok = false, message = "You cannot disable your own account." });
    }

    var ok = await authService.SetEnabledAsync(id, enabled, ct);
    return ok
        ? Results.Ok(new { ok = true })
        : Results.BadRequest(new { ok = false, message = "Unable to update user status." });
}).RequireAuthorization("AdminOnly");

app.MapPost("/admin/users/{id:guid}/enabled", async (Guid id, HttpContext httpContext, HttpRequest request, AuthService authService, CancellationToken ct) =>
{
    var currentUserIdRaw = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    var form = await request.ReadFormAsync(ct);
    var enabled = FormValues.LastBool(form["enabled"]);

    if (Guid.TryParse(currentUserIdRaw, out var currentUserId) && currentUserId == id && !enabled)
    {
        return Results.Redirect("/admin?msg=You%20cannot%20disable%20your%20own%20account");
    }

    var ok = await authService.SetEnabledAsync(id, enabled, ct);
    return Results.Redirect(ok ? "/admin?msg=User%20status%20updated" : "/admin?msg=Unable%20to%20update%20user");
}).RequireAuthorization("AdminOnly");

app.MapPost("/admin/users/{id:guid}/delete", async (Guid id, HttpContext httpContext, AuthService authService, CancellationToken ct) =>
{
    var currentUserIdRaw = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (Guid.TryParse(currentUserIdRaw, out var currentUserId) && currentUserId == id)
    {
        return Results.Redirect("/admin?msg=You%20cannot%20delete%20your%20own%20account");
    }

    var ok = await authService.DeleteUserAsync(id, ct);
    return Results.Redirect(ok ? "/admin?msg=User%20deleted" : "/admin?msg=Unable%20to%20delete%20user");
}).RequireAuthorization("AdminOnly");

app.MapPost("/admin/settings/registration", async (HttpRequest request, AuthService authService, CancellationToken ct) =>
{
    var form = await request.ReadFormAsync(ct);
    var enabled = FormValues.LastBool(form["enabled"]);
    await authService.SetAllowRegistrationAsync(enabled, ct);
    return Results.Redirect($"/admin?msg={(enabled ? "Registration%20enabled" : "Registration%20disabled")}");
}).RequireAuthorization("AdminOnly");

app.MapPost("/shares/{id:guid}/delete", async (Guid id, HttpContext context, ShareManager manager, CancellationToken ct) =>
{
    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    var ok = await manager.DeleteShareAsync(id, owner, ct);
    return Results.Redirect(ok ? "/?msg=Share%20deleted" : "/?msg=Unable%20to%20delete%20share");
}).RequireAuthorization();

app.MapPost("/shares/delete-batch", async (HttpContext context, ShareManager manager, HttpRequest request, CancellationToken ct) =>
{
    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    if (!request.HasFormContentType)
    {
        return Results.Redirect("/?msg=No%20shares%20selected");
    }

    var form = await request.ReadFormAsync(ct);
    var shareIds = form["shareIds"]
        .Select(value => value?.Trim())
        .Where(value => !string.IsNullOrWhiteSpace(value))
        .Select(value => Guid.TryParse(value, out var parsed) ? parsed : Guid.Empty)
        .Where(value => value != Guid.Empty)
        .Distinct()
        .ToArray();

    if (shareIds.Length == 0)
    {
        return Results.Redirect("/?msg=No%20shares%20selected");
    }

    var deleted = 0;
    foreach (var shareId in shareIds)
    {
        if (await manager.DeleteShareAsync(shareId, owner, ct))
        {
            deleted += 1;
        }
    }

    return Results.Redirect($"/?msg={Uri.EscapeDataString($"Deleted {deleted} share(s)")}");
}).RequireAuthorization();

app.MapPost("/shares/{id:guid}/reenable", async (Guid id, HttpContext context, ShareManager manager, CancellationToken ct) =>
{
    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    var ok = await manager.ReenableShareFor24HoursAsync(id, owner, ct);
    return Results.Redirect(ok
        ? "/?msg=Share%20re-enabled%20for%2024%20hours"
        : "/?msg=Unable%20to%20re-enable%20share");
}).RequireAuthorization();

app.MapPost("/shares/{id:guid}/show-link", async (Guid id, HttpContext context, ShareManager manager, CancellationToken ct) =>
{
    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    var token = await manager.GetCopyableShareTokenAsync(id, owner, ct);
    if (string.IsNullOrWhiteSpace(token))
    {
        return Results.Redirect("/?msg=Unable%20to%20open%20share%20link");
    }

    return Results.Redirect($"/shares/created/{Uri.EscapeDataString(token)}");
}).RequireAuthorization();

app.MapGet("/api/shares/{token}/status", async (string token, HttpContext context, ShareManager manager, ShareCreationStatusStore statusStore, CancellationToken ct) =>
{
    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    var share = await manager.FindByTokenAsync(token, ct);
    if (share is not null)
    {
        if (!owner.Owns(share.OwnerUserId))
        {
            return Results.NotFound();
        }

        return Results.Ok(new
        {
            state = "completed",
            ready = true,
            steps = Array.Empty<object>()
        });
    }

    var status = statusStore.Read(token);
    if (status is null || status.OwnerUserId != owner.UserId)
    {
        return Results.NotFound();
    }

    return Results.Ok(new
    {
        state = status.State,
        ready = string.Equals(status.State, "completed", StringComparison.OrdinalIgnoreCase),
        error = status.Error,
        steps = status.Steps.Select(step => new
        {
            key = step.Key,
            label = step.Label,
            state = step.State,
            detail = step.Detail,
            updatedAtUtc = step.UpdatedAtUtc
        }).ToArray()
    });
}).RequireAuthorization();

app.MapPost("/api/account/template", async (HttpContext context, ShareManager manager, IOptions<AgoraOptions> agoraOptions, ScratchSpaceMonitor scratchSpace, HttpRequest request, CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest("Expected multipart/form-data");
    }

    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    var cfg = agoraOptions.Value;
    // Like the stage endpoints: the multipart body is buffered into scratch, so that space is reserved before it is read.
    try
    {
        UploadStagingEndpoints.ReserveRequestBuffer(context, scratchSpace, cfg.MaxFileSizeBytes);
    }
    catch (UploadLimitException ex)
    {
        return Results.Redirect($"/account/landing-page-designer?msg={Uri.EscapeDataString(ex.Message)}");
    }

    var form = await request.ReadFormAsync(ct);
    var existingTemplate = await manager.GetAccountTemplateAsync(owner, ct);
    var backgroundImageUrl = existingTemplate.BackgroundImageUrl;
    var backgroundColorMode = form["backgroundColorMode"].ToString();
    var backgroundColorHex = string.Equals(backgroundColorMode, "custom", StringComparison.OrdinalIgnoreCase)
        ? NormalizeHexColor(form["backgroundColorHex"].ToString())
        : null;
    var containerPosition = NormalizeContainerPosition(form["containerPosition"].ToString());
    var backgroundImageFile = form.Files["backgroundImageFile"];
    if (backgroundImageFile is not null && backgroundImageFile.Length > 0)
    {
        if (!ContentTypePolicy.IsAllowedBackgroundImage(backgroundImageFile.FileName))
        {
            return Results.Redirect("/account/landing-page-designer?msg=Only%20JPG%2C%20PNG%2C%20or%20WEBP%20images%20are%20allowed");
        }

        if (backgroundImageFile.Length > cfg.MaxFileSizeBytes)
        {
            return Results.Redirect("/account/landing-page-designer?msg=The%20background%20image%20is%20too%20large");
        }

        var safeName = ArchiveNameResolver.Sanitize(backgroundImageFile.FileName);
        var extension = Path.GetExtension(safeName);
        if (string.IsNullOrWhiteSpace(extension))
        {
            extension = ".jpg";
        }

        var key = $"uploads/templates/general/{Guid.NewGuid():N}{extension}";
        var storageRoot = cfg.StorageRoot;
        // Scratch copy plus, with the FileSystem store, the durable object on the same volume.
        ScratchReservation backgroundReservation;
        try
        {
            backgroundReservation = scratchSpace.Reserve(new ScratchDemand(backgroundImageFile.Length, scratchSpace.DurableDemand(backgroundImageFile.Length).DurableBytes));
        }
        catch (UploadLimitException ex)
        {
            return Results.Redirect($"/account/landing-page-designer?msg={Uri.EscapeDataString(ex.Message)}");
        }

        using var _ = backgroundReservation;
        var scratchPath = ScratchFiles.NewPath(storageRoot, extension);
        try
        {
            await using (var stream = File.Create(scratchPath))
            {
                await backgroundImageFile.CopyToAsync(stream, ct);
            }

            await context.RequestServices.GetRequiredService<IObjectStore>()
                .PutFileAsync(key, scratchPath, ContentTypePolicy.FromFileName(safeName), ct);
        }
        finally
        {
            ScratchFiles.TryDelete(scratchPath);
        }

        backgroundImageUrl = $"internal:{key}";
    }

    await manager.UpsertAccountTemplateAsync(owner, new ShareTemplateData(
        string.IsNullOrWhiteSpace(form["title"].ToString()) ? "Shared file" : form["title"].ToString(),
        string.IsNullOrWhiteSpace(form["h1"].ToString()) ? "A file was shared with you" : form["h1"].ToString(),
        string.IsNullOrWhiteSpace(form["description"].ToString()) ? "Use the button below to download your file." : form["description"].ToString(),
        backgroundImageUrl,
        backgroundColorHex,
        containerPosition), ct);

    return Results.Redirect("/account/landing-page-designer?msg=Template%20saved");
}).RequireAuthorization()
  .WithMetadata(new UploadEndpointMetadata(RequiresHeaderCsrfToken: true), new RequestSizeLimitAttribute(stageRequestBodyLimit));

app.MapPost("/api/share-drafts/{draftShareId}/template", async (HttpContext context, ShareManager manager, string draftShareId, HttpRequest request, CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest("Expected form data");
    }

    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }
    try
    {
        draftShareId = await manager.EnsureDraftShareAsync(owner.UserId, draftShareId, ct);
    }
    catch (Exception ex) when (ex is InvalidOperationException or UploadLimitException)
    {
        return Results.Redirect($"/shares/new?msg={Uri.EscapeDataString(ex.Message)}");
    }

    var form = await request.ReadFormAsync(ct);
    var template = new ShareTemplateData(
        string.IsNullOrWhiteSpace(form["title"].ToString()) ? "Shared file" : form["title"].ToString(),
        string.IsNullOrWhiteSpace(form["h1"].ToString()) ? "A file was shared with you" : form["h1"].ToString(),
        string.IsNullOrWhiteSpace(form["description"].ToString()) ? "Use the button below to download your file." : form["description"].ToString(),
        null,
        NormalizeHexColor(form["backgroundColorHex"].ToString()),
        NormalizeContainerPosition(form["containerPosition"].ToString()));

    var backgroundUploadId = form["backgroundUploadId"].ToString().Trim();
    if (!string.IsNullOrWhiteSpace(backgroundUploadId))
    {
        try
        {
            await manager.ResolveStagedUploadsAsync(
                owner.UserId,
                [backgroundUploadId],
                draftShareId,
                ct,
                ShareManager.UploadPurposeTemplateBackground);
        }
        catch (InvalidOperationException ex)
        {
            return Results.Redirect($"/share/landing-page-designer?draftShareId={Uri.EscapeDataString(draftShareId)}&msg={Uri.EscapeDataString(ex.Message)}");
        }
    }

    await manager.SaveDraftTemplateAsync(owner.UserId, draftShareId, "per_upload", template, backgroundUploadId, ct);
    return Results.Redirect($"/shares/new?draftShareId={Uri.EscapeDataString(draftShareId)}&msg=Share%20design%20saved");
}).RequireAuthorization();

app.MapGet("/api/share-drafts/{draftShareId}/background-preview", async (HttpContext context, ShareManager manager, string draftShareId, string uploadId, CancellationToken ct) =>
{
    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    if (string.IsNullOrWhiteSpace(uploadId))
    {
        return Results.BadRequest();
    }

    IReadOnlyList<ShareManager.StagedUploadFile> staged;
    try
    {
        staged = await manager.ResolveStagedUploadsAsync(
            owner.UserId,
            [uploadId],
            draftShareId,
            ct,
            ShareManager.UploadPurposeTemplateBackground);
    }
    catch (InvalidOperationException)
    {
        return Results.NotFound();
    }

    var file = staged.SingleOrDefault();
    if (file is null || !File.Exists(file.TempPath))
    {
        return Results.NotFound();
    }

    return ObjectResults.UserContentFile(context.Response, file.TempPath, file.OriginalFileName);
}).RequireAuthorization();

app.MapPost("/api/account/settings", async (HttpContext context, AuthService authService, HttpRequest request, CancellationToken ct) =>
{
    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    var form = await request.ReadFormAsync(ct);
    var defaultNotifyMode = form["defaultNotifyMode"].ToString();
    var defaultExpiryMode = form["defaultExpiryMode"].ToString();
    var notifyOk = await authService.SetDefaultNotifyModeAsync(owner.UserId, defaultNotifyMode, ct);
    var expiryOk = await authService.SetDefaultExpiryModeAsync(owner.UserId, defaultExpiryMode, ct);
    var ok = notifyOk && expiryOk;
    return Results.Redirect(ok ? "/account/settings?msg=Account%20defaults%20saved" : "/account/settings?msg=Unable%20to%20save%20account%20defaults");
}).RequireAuthorization();

app.MapGet("/account/template/background", async (HttpContext context, ShareManager manager, IObjectStore objectStore, CancellationToken ct) =>
{
    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    var template = await manager.GetAccountTemplateAsync(owner, ct);
    var key = ObjectKey.FromInternalMarker(template.BackgroundImageUrl);
    if (key is null || await objectStore.OpenReadAsync(key, ct) is not { } background)
    {
        return Results.NotFound();
    }

    return ObjectResults.UserContent(context.Response, background, key);
}).RequireAuthorization();

app.MapUploadStagingEndpoints(stageRequestBodyLimit);

app.MapPost("/api/public-uploads/create-share", async (
    AuthService authService,
    ShareManager manager,
    ScratchSpaceMonitor scratchSpace,
    IOptions<AgoraOptions> options,
    QueuedShareCreationJob queuedShareCreationJob,
    HttpContext context,
    HttpRequest request,
    CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest("Expected form data.");
    }

    var form = await request.ReadFormAsync(ct);
    var uploadToken = form["uploadToken"].ToString().Trim();
    var draftShareId = form["draftShareId"].ToString().Trim();
    // Sender text is stored (SenderName 200, SenderEmail 320 columns) and shown on the page and in mail.
    var senderName = NormalizeSenderText(form["senderName"].ToString());
    var senderEmail = EmailAddress.Normalize(NormalizeSenderText(form["senderEmail"].ToString()));
    var senderMessage = form["senderMessage"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(uploadToken) || string.IsNullOrWhiteSpace(draftShareId))
    {
        return Results.BadRequest("uploadToken and draftShareId are required.");
    }

    if (string.IsNullOrWhiteSpace(senderName))
    {
        return Results.BadRequest("senderName is required.");
    }

    if (senderName.Length > 200)
    {
        return Results.BadRequest("senderName must be at most 200 characters.");
    }

    if (senderEmail.Length > 320 || !IsValidEmailAddress(senderEmail))
    {
        return Results.BadRequest("senderEmail must be a valid email address.");
    }

    var user = await authService.FindByUploadTokenAsync(uploadToken, ct);
    if (user is null)
    {
        return Results.NotFound("Upload link not found.");
    }

    try
    {
        draftShareId = await manager.EnsurePublicUploadDraftAsync(user.Id, draftShareId, user.UploadToken, ClientAddress(context), ct);
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(ex.Message);
    }
    catch (UploadLimitException ex)
    {
        return UploadLimitText(ex);
    }

    var uploadedFileIds = form["uploadedFileIds"]
        .Select(x => x?.Trim())
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Cast<string>()
        .ToArray();

    IReadOnlyList<ShareManager.StagedUploadFile> stagedUploads;
    try
    {
        stagedUploads = await manager.ResolveStagedUploadsAsync(user.Id, uploadedFileIds, draftShareId, ct);
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(ex.Message);
    }

    if (stagedUploads.Count == 0)
    {
        return Results.BadRequest("At least one file is required.");
    }

    var cfg = options.Value;
    if (stagedUploads.Count > cfg.MaxFilesPerShare)
    {
        return Results.BadRequest($"Too many files. Max {cfg.MaxFilesPerShare}.");
    }

    var total = 0L;
    foreach (var staged in stagedUploads)
    {
        if (staged.OriginalSizeBytes > cfg.MaxFileSizeBytes)
        {
            return Results.BadRequest($"File '{staged.OriginalFileName}' exceeds max size.");
        }

        total += staged.OriginalSizeBytes;
    }

    if (total > cfg.MaxTotalUploadBytes)
    {
        return Results.BadRequest("Total upload size exceeds limit.");
    }

    // The queued job builds the archive; refuse now rather than fail the job later (the job reserves the space).
    try
    {
        scratchSpace.EnsureCanAdmit(scratchSpace.ArchiveDemand(total, passwordProtected: false));
    }
    catch (UploadLimitException ex)
    {
        return UploadLimitText(ex);
    }

    // Fast path for the daily budget of received shares (counted per owner account, so rotating the code does not
    // reset it); the job re-checks it under a per-owner lock before the share is committed.
    var nowUtc = DateTime.UtcNow;
    var usage = await manager.GetReceivedShareUsageAsync(ShareOwner.For(user.Id, user.Email), nowUtc.AddHours(-24), ct);
    var quotaError = PublicUploadPolicy.CheckDailyQuota(usage.Count, usage.Bytes, total, cfg.PublicUploads);
    if (quotaError is not null)
    {
        return Results.Text(quotaError, statusCode: StatusCodes.Status429TooManyRequests);
    }

    var shareToken = await manager.GenerateUniqueShareTokenAsync(8, ct);
    if (isE2E)
    {
        var e2eShareTokenOverride = form["e2eShareTokenOverride"].ToString().Trim();
        if (IsValidShareToken(e2eShareTokenOverride))
        {
            shareToken = e2eShareTokenOverride;
        }
    }

    // Received shares follow the owner's default expiry; "indefinite" only when the owner chose it explicitly.
    var ownerExpiryMode = await authService.GetDefaultExpiryModeAsync(user.Id, ct);
    var expiry = PublicUploadPolicy.ResolveExpiry(ownerExpiryMode, cfg.PublicUploads.DefaultExpiryDays, nowUtc);
    var expiryModeRaw = expiry.Mode;
    var expiresAtUtc = expiry.ExpiresAtUtc;

    var notifyMode = await authService.GetDefaultNotifyModeAsync(user.Id, ct);
    if (notifyMode is not ("none" or "once" or "every_time"))
    {
        notifyMode = "once";
    }

    var publicUploadSubtitle = $"by {senderName} ({senderEmail})";
    var publicUploadDescription = string.IsNullOrWhiteSpace(senderMessage) ? null : senderMessage;

    var queued = new QueuedShareCreationJob.Payload(
        UploaderEmail: user.Email,
        DraftShareId: draftShareId,
        ShareToken: shareToken,
        Message: null,
        SenderName: senderName,
        SenderEmail: senderEmail,
        SenderMessage: string.IsNullOrWhiteSpace(senderMessage) ? null : senderMessage,
        DownloadPassword: null,
        ShowPreviews: true,
        ZipFileName: null,
        NotifyMode: notifyMode,
        ExpiryMode: expiryModeRaw,
        ExpiresAtUtc: expiresAtUtc,
        TemplateMode: "per_upload",
        TemplateTitle: publicUploadSubtitle,
        TemplateH1: null,
        TemplateDescription: publicUploadDescription,
        TemplateBackgroundColorHex: null,
        TemplateContainerPosition: null,
        TemplateBackgroundUploadId: null,
        UploadedFileIds: uploadedFileIds,
        OwnerUserId: user.Id);

    // Sealing stops further staging into this draft and makes a second submission of it a 409; a failed enqueue
    // unseals it again and reports 503 so the sender can retry.
    try
    {
        if (!await manager.SealDraftForSubmissionAsync(user.Id, draftShareId, () => { queuedShareCreationJob.Queue(queued); return Task.CompletedTask; }, ct))
        {
            return Results.Text("This upload was already submitted.", statusCode: StatusCodes.Status409Conflict);
        }
    }
    catch (UploadLimitException ex)
    {
        return UploadLimitText(ex);
    }

    return Results.Redirect($"/u/{Uri.EscapeDataString(uploadToken)}?submitted=1");
}).RequireRateLimiting(RateLimitSetup.PublicUploadEndpoints)
  .WithMetadata(new UploadEndpointMetadata(RequiresHeaderCsrfToken: false), new RequestSizeLimitAttribute(createRequestBodyLimit));

app.MapPost("/api/uploads/remove", async (
    HttpContext context,
    ShareManager manager,
    HttpRequest request,
    CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest(new { error = "Expected form data." });
    }

    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    var form = await request.ReadFormAsync(ct);
    var draftShareId = form["draftShareId"].ToString().Trim();
    var uploadId = form["uploadId"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(draftShareId) || string.IsNullOrWhiteSpace(uploadId))
    {
        return Results.BadRequest(new { error = "draftShareId and uploadId are required." });
    }

    var ok = await manager.DeleteStagedUploadAsync(owner.UserId, draftShareId, uploadId, ct);
    return ok
        ? Results.Ok(new { removed = true })
        : Results.NotFound(new { error = "Upload not found." });
}).RequireAuthorization();

app.MapPost("/api/uploads/cancel", async (
    HttpContext context,
    ShareManager manager,
    IBackgroundJobClient backgroundJobs,
    HttpRequest request,
    CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest(new { error = "Expected form data." });
    }

    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    var form = await request.ReadFormAsync(ct);
    var draftShareId = form["draftShareId"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(draftShareId))
    {
        return Results.BadRequest(new { error = "draftShareId is required." });
    }

    try
    {
        draftShareId = await manager.EnsureDraftShareAsync(owner.UserId, draftShareId, ct);
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
    catch (UploadLimitException ex)
    {
        return UploadLimitJson(ex);
    }

    var jobId = backgroundJobs.Enqueue<ShareManager>(x =>
        x.DeleteStagedUploadsForDraftAsync(owner.UserId, draftShareId, CancellationToken.None));

    return Results.Ok(new { canceled = true, cleanupJobId = jobId });
}).RequireAuthorization();

app.MapPost("/api/shares", async (
    HttpContext context,
    ShareManager manager,
    AuthService authService,
    ScratchSpaceMonitor scratchSpace,
    IOptions<AgoraOptions> options,
    QueuedShareCreationJob queuedShareCreationJob,
    HttpRequest request,
    CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest("Expected multipart/form-data");
    }

    if (!context.User.TryGetShareOwner(out var owner))
    {
        return Results.Unauthorized();
    }

    var uploaderEmail = owner.Email;
    var cfg = options.Value;
    // API clients may post files directly here (the UI stages first), so the multipart buffer is reserved against
    // the scratch budget before the body is read, like on the stage endpoints.
    try
    {
        UploadStagingEndpoints.ReserveRequestBuffer(context, scratchSpace, cfg.MaxTotalUploadBytes);
    }
    catch (UploadLimitException ex)
    {
        return UploadLimitText(ex);
    }

    var form = await request.ReadFormAsync(ct);
    var draftShareId = form["draftShareId"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(draftShareId))
    {
        return Results.BadRequest("draftShareId is required");
    }

    try
    {
        draftShareId = await manager.EnsureDraftShareAsync(owner.UserId, draftShareId, ct);
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(ex.Message);
    }
    catch (UploadLimitException ex)
    {
        return UploadLimitText(ex);
    }

    var shareToken = form["shareToken"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(shareToken))
    {
        shareToken = await manager.GenerateUniqueShareTokenAsync(8, ct);
    }

    if (!IsValidShareToken(shareToken))
    {
        return Results.Redirect($"/shares/new?draftShareId={Uri.EscapeDataString(draftShareId)}&shareToken={Uri.EscapeDataString(shareToken)}&msg=Share%20link%20must%20be%208-64%20letters%2C%20numbers%2C%20hyphens%2C%20or%20underscores");
    }

    var isShareTokenAvailable = await manager.IsShareTokenAvailableAsync(shareToken, ct);
    if (!isShareTokenAvailable)
    {
        var suggestedShareToken = await manager.GenerateUniqueShareTokenAsync(8, ct);
        return Results.Redirect($"/shares/new?draftShareId={Uri.EscapeDataString(draftShareId)}&shareToken={Uri.EscapeDataString(shareToken)}&suggestedShareToken={Uri.EscapeDataString(suggestedShareToken)}&msg=That%20share%20link%20is%20already%20in%20use");
    }

    var files = form.Files;
    if (files.Count > 0)
    {
        return Results.BadRequest("Please wait for file uploads to finish before creating the share.");
    }

    var uploadedFileIds = form["uploadedFileIds"]
        .Select(x => x?.Trim())
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Cast<string>()
        .ToArray();

    IReadOnlyList<ShareManager.StagedUploadFile> stagedUploads;
    try
    {
        stagedUploads = await manager.ResolveStagedUploadsAsync(owner.UserId, uploadedFileIds, draftShareId, ct);
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(ex.Message);
    }

    if (files.Count == 0 && stagedUploads.Count == 0)
    {
        return Results.BadRequest("At least one file is required");
    }

    if (files.Count + stagedUploads.Count > cfg.MaxFilesPerShare)
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

    foreach (var staged in stagedUploads)
    {
        if (staged.OriginalSizeBytes > cfg.MaxFileSizeBytes)
        {
            return Results.BadRequest($"File '{staged.OriginalFileName}' exceeds max size");
        }

        total += staged.OriginalSizeBytes;
    }

    if (total > cfg.MaxTotalUploadBytes)
    {
        return Results.BadRequest("Total upload size exceeds limit");
    }

    var expiryModeRaw = form["expiryMode"].ToString().Trim().ToLowerInvariant();
    if (expiryModeRaw == "account_default")
    {
        expiryModeRaw = await authService.GetDefaultExpiryModeAsync(owner.UserId, ct);
    }
    var nowUtc = DateTime.UtcNow;
    DateTime? expiresAtUtc = expiryModeRaw switch
    {
        "1_hour" => nowUtc.AddHours(1),
        "24_hours" => nowUtc.AddHours(24),
        "7_days" => nowUtc.AddDays(7),
        "30_days" => nowUtc.AddDays(30),
        "1_year" => nowUtc.AddYears(1),
        "indefinite" => null,
        _ => null
    };

    if (expiryModeRaw == "date")
    {
        var value = form["expiresAtUtc"].ToString();
        if (!DateTime.TryParse(value, out var parsed))
        {
            return Results.BadRequest("expiresAtUtc is required for date mode");
        }

        expiresAtUtc = DateTime.SpecifyKind(parsed, DateTimeKind.Local).ToUniversalTime();
        if (expiresAtUtc <= nowUtc)
        {
            return Results.BadRequest("expiresAtUtc must be in the future");
        }
    }
    else if (expiryModeRaw is not ("1_hour" or "24_hours" or "7_days" or "30_days" or "1_year" or "indefinite"))
    {
        return Results.BadRequest("expiryMode must be 1_hour|24_hours|7_days|30_days|1_year|date|indefinite");
    }

    var notifyModeRaw = form["notifyMode"].ToString().Trim().ToLowerInvariant();
    var notifyMode = notifyModeRaw == "account_default"
        ? await authService.GetDefaultNotifyModeAsync(owner.UserId, ct)
        : notifyModeRaw;
    if (notifyMode is not ("none" or "once" or "every_time"))
    {
        return Results.BadRequest("notifyMode must be account_default|none|once|every_time");
    }

    var downloadPasswordRaw = form["downloadPassword"].ToString();
    if (!TryNormalizeOptionalSharePassword(downloadPasswordRaw, out var downloadPassword))
    {
        return Results.BadRequest("downloadPassword must be at least 8 characters when provided");
    }

    var showPreviews = IsTruthy(form["showPreviews"].ToString());

    var templateModeRaw = form["templateMode"].ToString();
    var templateMode = string.Equals(templateModeRaw, "per_upload", StringComparison.OrdinalIgnoreCase)
        ? TemplateMode.PerUpload
        : TemplateMode.AccountDefault;

    var templateBackgroundUploadId = form["template.backgroundUploadId"].ToString().Trim();
    long templateBackgroundBytes = 0;
    if (!string.IsNullOrWhiteSpace(templateBackgroundUploadId))
    {
        try
        {
            var stagedBackground = await manager.ResolveStagedUploadsAsync(
                owner.UserId,
                [templateBackgroundUploadId],
                draftShareId,
                ct,
                ShareManager.UploadPurposeTemplateBackground);
            templateBackgroundBytes = stagedBackground.Sum(x => x.OriginalSizeBytes);
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(ex.Message);
        }
    }

    // The queued job builds the archive; refuse now rather than fail the job later (the job reserves the space).
    try
    {
        scratchSpace.EnsureCanAdmit(scratchSpace.ArchiveDemand(total, passwordProtected: downloadPassword is not null, backgroundBytes: templateBackgroundBytes));
    }
    catch (UploadLimitException ex)
    {
        return UploadLimitText(ex);
    }

    var queued = new QueuedShareCreationJob.Payload(
        UploaderEmail: uploaderEmail,
        DraftShareId: draftShareId,
        ShareToken: shareToken,
        Message: form["message"].ToString(),
        SenderName: null,
        SenderEmail: null,
        SenderMessage: null,
        DownloadPassword: downloadPassword,
        ShowPreviews: showPreviews,
        ZipFileName: form["zipFileName"].ToString(),
        NotifyMode: notifyMode,
        ExpiryMode: expiryModeRaw,
        ExpiresAtUtc: expiresAtUtc,
        TemplateMode: templateMode == TemplateMode.PerUpload ? "per_upload" : "account_default",
        TemplateTitle: form["template.title"].ToString(),
        TemplateH1: form["template.h1"].ToString(),
        TemplateDescription: form["template.description"].ToString(),
        TemplateBackgroundColorHex: NormalizeHexColor(form["template.backgroundColorHex"].ToString()),
        TemplateContainerPosition: NormalizeContainerPosition(form["template.containerPosition"].ToString()),
        TemplateBackgroundUploadId: templateBackgroundUploadId,
        UploadedFileIds: uploadedFileIds,
        OwnerUserId: owner.UserId);

    // Sealing stops further staging into this draft and makes a second submission of it a 409; a failed enqueue
    // unseals it again and reports 503 so the user can retry.
    try
    {
        if (!await manager.SealDraftForSubmissionAsync(owner.UserId, draftShareId, () => { queuedShareCreationJob.Queue(queued); return Task.CompletedTask; }, ct))
        {
            return Results.Text("This share was already submitted.", statusCode: StatusCodes.Status409Conflict);
        }
    }
    catch (UploadLimitException ex)
    {
        return UploadLimitText(ex);
    }

    return Results.Redirect($"/shares/created/{Uri.EscapeDataString(shareToken)}");
}).RequireAuthorization()
  .WithMetadata(new UploadEndpointMetadata(RequiresHeaderCsrfToken: false), new RequestSizeLimitAttribute(configuredMaxTotalUploadBytes + 1024 * 1024));

// Anonymous share summary: only what the download page itself shows. No uploader message, page text, or storage markers.
app.MapGet("/api/shares/{token}", async (ShareManager manager, string token, CancellationToken ct) =>
{
    var share = await manager.FindByTokenAsync(token, ct);
    if (share is null || ShareManager.IsDeleted(share))
    {
        return Results.NotFound();
    }

    // A direct link has no download page to summarize.
    if (ShareModes.IsDirectLink(share.AccessMode))
    {
        return Results.NotFound();
    }

    if (ShareManager.IsExpired(share, DateTime.UtcNow))
    {
        return Results.StatusCode(StatusCodes.Status410Gone);
    }

    if (!string.IsNullOrWhiteSpace(share.DownloadPasswordHash))
    {
        // Nothing about the content until the password is presented on the download page.
        return Results.Ok(new { RequiresPassword = true, share.ExpiresAtUtc });
    }

    return Results.Ok(new
    {
        share.ZipDisplayName,
        share.ZipSizeBytes,
        FileCount = share.Files.Count,
        share.ShareExperienceType,
        share.AccessMode,
        RequiresPassword = false,
        share.ExpiresAtUtc
    });
});


app.MapPublicShareEndpoints();
app.MapDirectLinkEndpoints();
app.MapHub<ShareProgressHub>("/hubs/share-progress").RequireAuthorization();

app.Run();

static IResult UploadLimitJson(UploadLimitException ex) => UploadStagingEndpoints.UploadLimitJson(ex);

static IResult UploadLimitText(UploadLimitException ex) => UploadStagingEndpoints.UploadLimitText(ex);

static string ClientAddress(HttpContext context) => UploadStagingEndpoints.ClientAddress(context);

// Custom share tokens: at least 8 ASCII letters, digits, '-' or '_' so short, guessable links cannot be enumerated.
static bool IsValidShareToken(string token) => ShareTokens.IsValid(token);

// Strips control characters and collapses whitespace runs; sender text ends up in page markup and mail.
static string NormalizeSenderText(string? raw)
{
    var builder = new StringBuilder((raw ?? string.Empty).Length);
    var pendingSpace = false;
    foreach (var ch in raw ?? string.Empty)
    {
        if (char.IsWhiteSpace(ch))
        {
            pendingSpace = builder.Length > 0;
            continue;
        }

        if (char.IsControl(ch))
        {
            continue;
        }

        if (pendingSpace)
        {
            builder.Append(' ');
            pendingSpace = false;
        }

        builder.Append(ch);
    }

    return builder.ToString();
}

static bool IsTruthy(string? raw)
{
    var value = (raw ?? string.Empty).Trim().ToLowerInvariant();
    return value is "1" or "true" or "on" or "yes";
}

static bool IsValidEmailAddress(string? value)
{
    try
    {
        var normalized = (value ?? string.Empty).Trim();
        var parsed = new MailAddress(normalized);
        return string.Equals(parsed.Address, normalized, StringComparison.OrdinalIgnoreCase);
    }
    catch
    {
        return false;
    }
}

static bool TryNormalizeOptionalSharePassword(string? raw, out string? password)
{
    password = string.IsNullOrWhiteSpace(raw) ? null : raw.Trim();
    if (password is null)
    {
        return true;
    }

    return password.Length >= 8 && password.Length <= 256;
}


static string? NormalizeHexColor(string? value)
{
    var trimmed = (value ?? string.Empty).Trim();
    if (trimmed.Length == 0)
    {
        return null;
    }

    if (trimmed[0] != '#')
    {
        trimmed = "#" + trimmed;
    }

    if (trimmed.Length != 7)
    {
        return null;
    }

    for (var i = 1; i < trimmed.Length; i++)
    {
        var c = trimmed[i];
        var isHex = (c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F');
        if (!isHex)
        {
            return null;
        }
    }

    return trimmed.ToLowerInvariant();
}

static string NormalizeContainerPosition(string? value)
{
    var normalized = (value ?? string.Empty).Trim().ToLowerInvariant();
    return normalized switch
    {
        "center" => "center",
        "top_left" => "top_left",
        "top_right" => "top_right",
        "bottom_left" => "bottom_left",
        "bottom_right" => "bottom_right",
        "center_right" => "center_right",
        "center_left" => "center_left",
        "center_top" => "center_top",
        "center_bottom" => "center_bottom",
        _ => "center"
    };
}

static IConfiguration WithoutSerilogSinks(IConfiguration configuration)
{
    // Sinks are built in code; drop Serilog:WriteTo/Using so legacy overrides such as
    // Serilog__WriteTo__0__Args__path (still honoured by LogFileOptions) cannot create a nameless sink.
    var settings = configuration.GetSection("Serilog").AsEnumerable()
        .Where(x => !IsUnder(x.Key, "Serilog:WriteTo") && !IsUnder(x.Key, "Serilog:Using"));
    return new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

    static bool IsUnder(string key, string section) =>
        string.Equals(key, section, StringComparison.OrdinalIgnoreCase) ||
        key.StartsWith(section + ConfigurationPath.KeyDelimiter, StringComparison.OrdinalIgnoreCase);
}
