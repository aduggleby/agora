using System.Security.Claims;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Web.Auth;
using Agora.Web.Endpoints;
using Agora.Web.Hubs;
using Agora.Web.Services;
using Agora.Web.Startup;
using Agora.Web.Hangfire;
using Hangfire.Console;
using Hangfire;
using Hangfire.Dashboard;
using Hangfire.InMemory;
using Hangfire.SqlServer;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Serilog;
using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

var initialUploadLimits = builder.Configuration.GetSection(AgoraOptions.Section);
var configuredMaxFileSizeBytes = initialUploadLimits.GetValue<long?>("MaxFileSizeBytes") ?? (5L * 1024 * 1024 * 1024);
var configuredMaxTotalUploadBytes = initialUploadLimits.GetValue<long?>("MaxTotalUploadBytes") ?? (10L * 1024 * 1024 * 1024);
var maxRequestBodySize = Math.Max(configuredMaxFileSizeBytes, configuredMaxTotalUploadBytes);
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = maxRequestBodySize;
});

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
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "agora.csrf";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.FormFieldName = "__RequestVerificationToken";
    options.HeaderName = "X-CSRF-TOKEN";
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = static (context, _) =>
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            var seconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
            context.HttpContext.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
        }

        return ValueTask.CompletedTask;
    };

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        if (httpContext.User.Identity?.IsAuthenticated != true)
        {
            return RateLimitPartition.GetNoLimiter("anonymous");
        }

        var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)
                     ?? httpContext.User.FindFirstValue(ClaimTypes.Email)
                     ?? "authenticated";

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: $"authenticated:{userId}",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 120,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });

    options.AddPolicy("AuthEndpoints", httpContext =>
    {
        var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: $"auth:{ip}",
            factory: _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 4,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });

    options.AddPolicy("DownloadEndpoints", httpContext =>
    {
        var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var token = httpContext.Request.RouteValues.TryGetValue("token", out var tokenValue)
            ? tokenValue?.ToString() ?? "unknown"
            : "unknown";

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: $"download:{token}:{ip}",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });
});

var razorPages = builder.Services.AddRazorPages();
if (builder.Environment.IsDevelopment())
{
    razorPages.AddRazorRuntimeCompilation();
}

builder.Services.AddHangfire(configuration =>
{
    configuration.UseSimpleAssemblyNameTypeSerializer().UseRecommendedSerializerSettings().UseConsole();
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

builder.Services.AddHangfireServer(options =>
{
    options.Queues = ["default"];
});
builder.Services.AddHangfireServer(options =>
{
    options.Queues = ["previews"];
    options.WorkerCount = Math.Max(1, Environment.ProcessorCount / 4);
});
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<ShareManager>();
builder.Services.AddScoped<IShareContentStore, ShareContentStore>();
builder.Services.AddScoped<AuthEmailJob>();
builder.Services.AddScoped<EmailNotificationJob>();
builder.Services.AddScoped<QueuedShareCreationJob>();
builder.Services.AddScoped<SharePreviewJobService>();
builder.Services.AddSingleton<ShareCreationStatusStore>();
builder.Services.AddSingleton<ShareProgressBroadcaster>();
builder.Services.AddSingleton<SharePreviewImageGenerator>();
builder.Services.AddSignalR();
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
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor
        | ForwardedHeaders.XForwardedProto
        | ForwardedHeaders.XForwardedHost;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();
var isDevelopment = app.Environment.IsDevelopment();
var isE2E = builder.Configuration.GetValue<bool>("E2E:Enabled") ||
            string.Equals(Environment.GetEnvironmentVariable("AGORA_E2E"), "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Environment.GetEnvironmentVariable("AGORA_E2E"), "true", StringComparison.OrdinalIgnoreCase);

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
    try
    {
        await db.Database.MigrateAsync();
    }
    catch (Exception ex)
    {
        app.Logger.LogWarning(ex, "Automatic EF migration failed. Falling back to EnsureCreated for compatibility.");
        db.Database.EnsureCreated();
    }

    await SchemaUpgradeRunner.EnsureSchemaUpgradesAsync(db, CancellationToken.None);
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
app.UseStaticFiles();
app.Use(async (context, next) =>
{
    var antiforgery = context.RequestServices.GetRequiredService<IAntiforgery>();

    if (IsSafeHttpMethod(context.Request.Method))
    {
        var tokens = antiforgery.GetAndStoreTokens(context);
        if (!string.IsNullOrWhiteSpace(tokens.RequestToken))
        {
            context.Response.Cookies.Append("agora.csrf.request", tokens.RequestToken, new CookieOptions
            {
                HttpOnly = false,
                SameSite = SameSiteMode.Lax,
                Secure = context.Request.IsHttps,
                Path = "/"
            });
        }

        await next();
        return;
    }

    if (isE2E && context.Request.Path.StartsWithSegments("/api/e2e", StringComparison.OrdinalIgnoreCase))
    {
        await next();
        return;
    }

    if (context.Request.Path.StartsWithSegments("/hangfire", StringComparison.OrdinalIgnoreCase))
    {
        await next();
        return;
    }

    try
    {
        await antiforgery.ValidateRequestAsync(context);
    }
    catch (AntiforgeryValidationException ex)
    {
        app.Logger.LogWarning(
            ex,
            "CSRF validation failed for {Method} {Path}. IsHttps={IsHttps} Host={Host} Origin={Origin} Referer={Referer}",
            context.Request.Method,
            context.Request.Path,
            context.Request.IsHttps,
            context.Request.Host.Value,
            context.Request.Headers.Origin.ToString(),
            context.Request.Headers.Referer.ToString());
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new { error = "Invalid or missing CSRF token." });
        return;
    }

    await next();
});
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();
app.MapRazorPages();

app.MapHangfireDashboard("/hangfire", new DashboardOptions
{
    Authorization = new IDashboardAuthorizationFilter[] { new AdminDashboardAuthorizationFilter() }
}).RequireAuthorization("AdminOnly");


app.MapPost("/login", async (HttpContext httpContext, AuthService authService, IDataProtectionProvider dataProtectionProvider, CancellationToken ct) =>
{
    var form = await httpContext.Request.ReadFormAsync(ct);
    var email = form["email"].ToString();
    var password = form["password"].ToString();

    var result = await authService.LoginAsync(email, password, ct);
    if (!result.Success || result.User is null)
    {
        if (string.Equals(result.Error, AuthService.EmailConfirmationRequiredError, StringComparison.Ordinal))
        {
            var gateToken = LoginEmailConfirmationGate.Create(dataProtectionProvider, email);
            return Results.Redirect($"/confirm-email-required?email={Uri.EscapeDataString(email)}&gate={Uri.EscapeDataString(gateToken)}");
        }

        return Results.Redirect($"/login?msg={Uri.EscapeDataString(result.Error)}");
    }

    await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CreatePrincipal(result.User));
    return Results.Redirect("/");
}).RequireRateLimiting("AuthEndpoints");

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
        await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CreatePrincipal(result.User));
        return Results.Redirect("/");
    }).RequireRateLimiting("AuthEndpoints");
}


app.MapPost("/register", async (HttpContext httpContext, AuthService authService, CancellationToken ct) =>
{
    var form = await httpContext.Request.ReadFormAsync(ct);
    var email = form["email"].ToString();
    var password = form["password"].ToString();
    var publicBaseUrl = ResolvePublicBaseUrl(
        httpContext.RequestServices.GetRequiredService<IOptions<AgoraOptions>>().Value.PublicBaseUrl,
        httpContext.Request);
    var confirmUrlBase = $"{publicBaseUrl}/auth/confirm-email";

    var result = await authService.RegisterAsync(email, password, confirmUrlBase, ct);
    if (!result.Success)
    {
        return Results.Redirect($"/register?msg={Uri.EscapeDataString(result.Error)}");
    }

    return Results.Redirect("/login?msg=Check%20your%20email%20to%20confirm%20your%20account");
}).RequireRateLimiting("AuthEndpoints");

app.MapGet("/auth/confirm-email", async (AuthService authService, string email, string token, CancellationToken ct) =>
{
    var result = await authService.ConfirmEmailAsync(email, token, ct);
    return Results.Redirect(result.Success
        ? "/login?msg=Email%20confirmed.%20You%20can%20now%20sign%20in"
        : $"/login?msg={Uri.EscapeDataString(result.Error)}");
});

app.MapPost("/auth/resend-confirmation", async (HttpContext httpContext, AuthService authService, CancellationToken ct) =>
{
    if (!httpContext.Request.HasFormContentType)
    {
        return Results.Redirect("/login?msg=Please%20enter%20your%20email%20address");
    }

    var form = await httpContext.Request.ReadFormAsync(ct);
    var email = form["email"].ToString();
    var publicBaseUrl = ResolvePublicBaseUrl(
        httpContext.RequestServices.GetRequiredService<IOptions<AgoraOptions>>().Value.PublicBaseUrl,
        httpContext.Request);
    var confirmUrlBase = $"{publicBaseUrl}/auth/confirm-email";

    await authService.ResendEmailConfirmationAsync(email, confirmUrlBase, ct);
    return Results.Redirect("/login?msg=If%20the%20account%20is%20unconfirmed%2C%20a%20confirmation%20email%20was%20sent");
}).RequireRateLimiting("AuthEndpoints");

app.MapGet("/auth/confirm-email-change", async (HttpContext context, AuthService authService, string email, string token, CancellationToken ct) =>
{
    var result = await authService.ConfirmEmailChangeAsync(email, token, ct);
    if (!result.Success)
    {
        return Results.Redirect($"/account/settings?msg={Uri.EscapeDataString(result.Error)}");
    }

    if (context.User.Identity?.IsAuthenticated == true)
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    return Results.Redirect("/login?msg=Email%20updated.%20Please%20sign%20in%20again");
});

app.MapGet("/auth/confirm-password-change", async (HttpContext context, AuthService authService, string email, string token, CancellationToken ct) =>
{
    var result = await authService.ConfirmPasswordChangeAsync(email, token, ct);
    if (context.User.Identity?.IsAuthenticated == true)
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    return Results.Redirect(result.Success
        ? "/login?msg=Password%20updated.%20Please%20sign%20in%20again"
        : $"/login?msg={Uri.EscapeDataString(result.Error)}");
});

if (isE2E)
{
    app.MapPost("/api/e2e/users", async (AgoraDbContext db, HttpRequest request, CancellationToken ct) =>
    {
        if (!request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "Expected form data." });
        }

        var form = await request.ReadFormAsync(ct);
        var email = form["email"].ToString().Trim();
        var password = form["password"].ToString();
        var defaultNotifyMode = form["defaultNotifyMode"].ToString();
        var defaultExpiryMode = form["defaultExpiryMode"].ToString();

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

        db.Users.Add(new UserAccount
        {
            Id = Guid.NewGuid(),
            Email = email,
            EmailConfirmed = true,
            EmailConfirmedAtUtc = DateTime.UtcNow,
            PasswordHash = PasswordHasher.Hash(password),
            Role = "user",
            IsEnabled = true,
            CreatedAtUtc = DateTime.UtcNow,
            DefaultNotifyMode = string.IsNullOrWhiteSpace(defaultNotifyMode) ? "once" : defaultNotifyMode.Trim(),
            DefaultExpiryMode = string.IsNullOrWhiteSpace(defaultExpiryMode) ? "7_days" : defaultExpiryMode.Trim()
        });
        db.AccountTemplates.Add(new AccountTemplate
        {
            Id = Guid.NewGuid(),
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

        var hash = TokenCodec.HashToken(token);
        var share = await db.Shares.SingleOrDefaultAsync(x => x.ShareTokenHash == hash, ct);
        if (share is null)
        {
            return Results.NotFound(new { error = "Share not found." });
        }

        share.ExpiresAtUtc = DateTime.UtcNow.AddSeconds(seconds);
        await db.SaveChangesAsync(ct);
        return Results.Ok(new { share.Id, share.ExpiresAtUtc });
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
    var enabled = bool.TryParse(form["enabled"].ToString(), out var parsed) && parsed;

    if (Guid.TryParse(currentUserIdRaw, out var currentUserId) && currentUserId == id && !enabled)
    {
        return Results.BadRequest(new { ok = false, message = "You cannot disable your own account." });
    }

    var ok = await authService.SetEnabledAsync(id, enabled, ct);
    return ok
        ? Results.Ok(new { ok = true })
        : Results.BadRequest(new { ok = false, message = "Unable to update user status." });
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

app.MapPost("/shares/{id:guid}/delete", async (Guid id, HttpContext context, ShareManager manager, CancellationToken ct) =>
{
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Unauthorized();
    }

    var ok = await manager.DeleteShareAsync(id, email, ct);
    return Results.Redirect(ok ? "/?msg=Share%20deleted" : "/?msg=Unable%20to%20delete%20share");
}).RequireAuthorization();

app.MapPost("/shares/{id:guid}/reenable", async (Guid id, HttpContext context, ShareManager manager, CancellationToken ct) =>
{
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Unauthorized();
    }

    var ok = await manager.ReenableShareFor24HoursAsync(id, email, ct);
    return Results.Redirect(ok
        ? "/?msg=Share%20re-enabled%20for%2024%20hours"
        : "/?msg=Unable%20to%20re-enable%20share");
}).RequireAuthorization();

app.MapPost("/shares/{id:guid}/show-link", async (Guid id, HttpContext context, ShareManager manager, CancellationToken ct) =>
{
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Unauthorized();
    }

    var token = await manager.GetCopyableShareTokenAsync(id, email, ct);
    if (string.IsNullOrWhiteSpace(token))
    {
        return Results.Redirect("/?msg=Unable%20to%20open%20share%20link");
    }

    return Results.Redirect($"/shares/created?token={Uri.EscapeDataString(token)}");
}).RequireAuthorization();

app.MapGet("/api/shares/{token}/status", async (string token, HttpContext context, ShareManager manager, ShareCreationStatusStore statusStore, CancellationToken ct) =>
{
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Unauthorized();
    }

    var share = await manager.FindByTokenAsync(token, ct);
    if (share is not null)
    {
        if (!string.Equals(share.UploaderEmail, email, StringComparison.OrdinalIgnoreCase))
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
    if (status is null || !string.Equals(status.UploaderEmail, email, StringComparison.OrdinalIgnoreCase))
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

app.MapPost("/api/account/template", async (HttpContext context, ShareManager manager, HttpRequest request, CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest("Expected multipart/form-data");
    }

    var form = await request.ReadFormAsync(ct);
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Unauthorized();
    }

    var existingTemplate = await manager.GetAccountTemplateAsync(email, ct);
    var backgroundImageUrl = existingTemplate.BackgroundImageUrl;
    var backgroundColorMode = form["backgroundColorMode"].ToString();
    var backgroundColorHex = string.Equals(backgroundColorMode, "custom", StringComparison.OrdinalIgnoreCase)
        ? NormalizeHexColor(form["backgroundColorHex"].ToString())
        : null;
    var containerPosition = NormalizeContainerPosition(form["containerPosition"].ToString());
    var backgroundImageFile = form.Files["backgroundImageFile"];
    if (backgroundImageFile is not null && backgroundImageFile.Length > 0)
    {
        if (!IsAllowedBackgroundImageFileName(backgroundImageFile.FileName))
        {
            return Results.Redirect("/account/landing-page-designer?msg=Only%20JPG%2C%20PNG%2C%20SVG%2C%20or%20WEBP%20images%20are%20allowed");
        }

        var safeName = ArchiveNameResolver.Sanitize(backgroundImageFile.FileName);
        var extension = Path.GetExtension(safeName);
        if (string.IsNullOrWhiteSpace(extension))
        {
            extension = ".jpg";
        }

        var relativePath = Path.Combine("uploads", "templates", "general", $"{Guid.NewGuid():N}{extension}");
        var storageRoot = context.RequestServices.GetRequiredService<IOptions<AgoraOptions>>().Value.StorageRoot;
        var absolutePath = Path.Combine(storageRoot, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(absolutePath)!);
        await using (var stream = File.Create(absolutePath))
        {
            await backgroundImageFile.CopyToAsync(stream, ct);
        }

        backgroundImageUrl = $"internal:{relativePath.Replace('\\', '/')}";
    }

    await manager.UpsertAccountTemplateAsync(email, new ShareTemplateData(
        string.IsNullOrWhiteSpace(form["title"].ToString()) ? "Shared file" : form["title"].ToString(),
        string.IsNullOrWhiteSpace(form["h1"].ToString()) ? "A file was shared with you" : form["h1"].ToString(),
        string.IsNullOrWhiteSpace(form["description"].ToString()) ? "Use the button below to download your file." : form["description"].ToString(),
        backgroundImageUrl,
        backgroundColorHex,
        containerPosition), ct);

    return Results.Redirect("/account/landing-page-designer?msg=Template%20saved");
}).RequireAuthorization();

app.MapPost("/api/share-drafts/{draftShareId}/template", async (HttpContext context, ShareManager manager, string draftShareId, HttpRequest request, CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest("Expected form data");
    }

    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Unauthorized();
    }
    try
    {
        draftShareId = await manager.EnsureDraftShareAsync(email, draftShareId, ct);
    }
    catch (InvalidOperationException ex)
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
            await manager.ResolveStagedUploadsAsync(email, [backgroundUploadId], draftShareId, ct);
        }
        catch (InvalidOperationException ex)
        {
            return Results.Redirect($"/share/landing-page-designer?draftShareId={Uri.EscapeDataString(draftShareId)}&msg={Uri.EscapeDataString(ex.Message)}");
        }
    }

    await manager.SaveDraftTemplateAsync(email, draftShareId, "per_upload", template, backgroundUploadId, ct);
    return Results.Redirect($"/shares/new?draftShareId={Uri.EscapeDataString(draftShareId)}&msg=Share%20design%20saved");
}).RequireAuthorization();

app.MapGet("/api/share-drafts/{draftShareId}/background-preview", async (HttpContext context, ShareManager manager, string draftShareId, string uploadId, CancellationToken ct) =>
{
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
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
        staged = await manager.ResolveStagedUploadsAsync(email, [uploadId], draftShareId, ct);
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

    var contentType = string.IsNullOrWhiteSpace(file.ContentType)
        ? GuessImageContentType(Path.GetExtension(file.OriginalFileName))
        : file.ContentType;
    return Results.File(file.TempPath, contentType);
}).RequireAuthorization();

app.MapPost("/api/account/settings", async (HttpContext context, AuthService authService, HttpRequest request, CancellationToken ct) =>
{
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Unauthorized();
    }

    var form = await request.ReadFormAsync(ct);
    var defaultNotifyMode = form["defaultNotifyMode"].ToString();
    var defaultExpiryMode = form["defaultExpiryMode"].ToString();
    var notifyOk = await authService.SetDefaultNotifyModeAsync(email, defaultNotifyMode, ct);
    var expiryOk = await authService.SetDefaultExpiryModeAsync(email, defaultExpiryMode, ct);
    var ok = notifyOk && expiryOk;
    return Results.Redirect(ok ? "/account/settings?msg=Account%20defaults%20saved" : "/account/settings?msg=Unable%20to%20save%20account%20defaults");
}).RequireAuthorization();

app.MapGet("/account/template/background", async (HttpContext context, ShareManager manager, IOptions<AgoraOptions> options, CancellationToken ct) =>
{
    var email = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Unauthorized();
    }

    var template = await manager.GetAccountTemplateAsync(email, ct);
    var marker = template.BackgroundImageUrl ?? string.Empty;
    if (!marker.StartsWith("internal:", StringComparison.OrdinalIgnoreCase))
    {
        return Results.NotFound();
    }

    var relativePath = marker["internal:".Length..].TrimStart('/', '\\');
    var storageRoot = Path.GetFullPath(options.Value.StorageRoot);
    var absolutePath = Path.GetFullPath(Path.Combine(storageRoot, relativePath));
    if (!absolutePath.StartsWith(storageRoot, StringComparison.Ordinal))
    {
        return Results.NotFound();
    }

    if (!File.Exists(absolutePath))
    {
        return Results.NotFound();
    }

    return Results.File(absolutePath, GuessImageContentType(Path.GetExtension(absolutePath)));
}).RequireAuthorization();

app.MapPost("/api/uploads/stage", async (
    HttpContext context,
    ShareManager manager,
    IOptions<AgoraOptions> options,
    HttpRequest request,
    CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest(new { error = "Expected multipart/form-data." });
    }

    var uploaderEmail = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(uploaderEmail))
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
        draftShareId = await manager.EnsureDraftShareAsync(uploaderEmail, draftShareId, ct);
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }

    var file = form.Files["file"];
    if (file is null || file.Length <= 0)
    {
        return Results.BadRequest(new { error = "A file is required." });
    }

    var cfg = options.Value;
    if (file.Length > cfg.MaxFileSizeBytes)
    {
        return Results.BadRequest(new { error = $"File '{file.FileName}' exceeds max size." });
    }

    await using var stream = file.OpenReadStream();
    var staged = await manager.StageUploadAsync(
        uploaderEmail,
        draftShareId,
        file.FileName,
        file.Length,
        file.ContentType,
        stream,
        ct);

    return Results.Ok(new
    {
        uploadId = staged.UploadId,
        fileName = staged.OriginalFileName,
        sizeBytes = staged.OriginalSizeBytes
    });
}).RequireAuthorization();

app.MapPost("/api/uploads/stage-template-background", async (
    HttpContext context,
    ShareManager manager,
    IOptions<AgoraOptions> options,
    HttpRequest request,
    CancellationToken ct) =>
{
    if (!request.HasFormContentType)
    {
        return Results.BadRequest(new { error = "Expected multipart/form-data." });
    }

    var uploaderEmail = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(uploaderEmail))
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
        draftShareId = await manager.EnsureDraftShareAsync(uploaderEmail, draftShareId, ct);
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }

    var file = form.Files["file"];
    if (file is null || file.Length <= 0)
    {
        return Results.BadRequest(new { error = "An image file is required." });
    }

    if (!IsAllowedBackgroundImageFileName(file.FileName))
    {
        return Results.BadRequest(new { error = "Only JPG, PNG, SVG, or WEBP files are allowed." });
    }

    var cfg = options.Value;
    if (file.Length > cfg.MaxFileSizeBytes)
    {
        return Results.BadRequest(new { error = $"File '{file.FileName}' exceeds max size." });
    }

    await using var stream = file.OpenReadStream();
    var staged = await manager.StageUploadAsync(
        uploaderEmail,
        draftShareId,
        file.FileName,
        file.Length,
        file.ContentType,
        stream,
        ct);

    return Results.Ok(new
    {
        uploadId = staged.UploadId,
        fileName = staged.OriginalFileName,
        sizeBytes = staged.OriginalSizeBytes
    });
}).RequireAuthorization();

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

    var uploaderEmail = context.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(uploaderEmail))
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

    var ok = await manager.DeleteStagedUploadAsync(uploaderEmail, draftShareId, uploadId, ct);
    return ok
        ? Results.Ok(new { removed = true })
        : Results.NotFound(new { error = "Upload not found." });
}).RequireAuthorization();

app.MapPost("/api/shares", async (
    HttpContext context,
    ShareManager manager,
    AuthService authService,
    IOptions<AgoraOptions> options,
    QueuedShareCreationJob queuedShareCreationJob,
    HttpRequest request,
    CancellationToken ct) =>
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
    var draftShareId = form["draftShareId"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(draftShareId))
    {
        return Results.BadRequest("draftShareId is required");
    }

    try
    {
        draftShareId = await manager.EnsureDraftShareAsync(uploaderEmail, draftShareId, ct);
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(ex.Message);
    }

    var shareToken = form["shareToken"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(shareToken))
    {
        shareToken = await manager.GenerateUniqueShareTokenAsync(8, ct);
    }

    if (!IsValidShareToken(shareToken))
    {
        return Results.Redirect($"/shares/new?draftShareId={Uri.EscapeDataString(draftShareId)}&shareToken={Uri.EscapeDataString(shareToken)}&msg=Share%20link%20must%20be%203-64%20letters%2C%20numbers%2C%20hyphens%2C%20or%20underscores");
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

    var cfg = options.Value;
    IReadOnlyList<ShareManager.StagedUploadFile> stagedUploads;
    try
    {
        stagedUploads = await manager.ResolveStagedUploadsAsync(uploaderEmail, uploadedFileIds, draftShareId, ct);
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
        expiryModeRaw = await authService.GetDefaultExpiryModeAsync(uploaderEmail, ct);
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
        ? await authService.GetDefaultNotifyModeAsync(uploaderEmail, ct)
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
    if (!string.IsNullOrWhiteSpace(templateBackgroundUploadId))
    {
        try
        {
            await manager.ResolveStagedUploadsAsync(uploaderEmail, [templateBackgroundUploadId], draftShareId, ct);
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(ex.Message);
        }
    }

    var queued = new QueuedShareCreationJob.Payload(
        UploaderEmail: uploaderEmail,
        DraftShareId: draftShareId,
        ShareToken: shareToken,
        Message: form["message"].ToString(),
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
        UploadedFileIds: uploadedFileIds);

    queuedShareCreationJob.Queue(queued);
    return Results.Redirect($"/shares/created?token={Uri.EscapeDataString(shareToken)}");
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
        share.ShareExperienceType,
        share.AccessMode,
        RequiresPassword = !string.IsNullOrWhiteSpace(share.DownloadPasswordHash),
        UploaderMessage = share.UploaderMessage,
        Page = new
        {
            Title = share.PageTitle,
            H1 = share.PageH1,
            Description = share.PageDescription,
            share.BackgroundImageUrl,
            share.PageBackgroundColorHex,
            share.PageContainerPosition
        },
        share.ExpiresAtUtc,
        IsExpired = false
    });
});


app.MapPublicShareEndpoints();
app.MapHub<ShareProgressHub>("/hubs/share-progress").RequireAuthorization();

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

static bool IsSafeHttpMethod(string method)
{
    return HttpMethods.IsGet(method) ||
           HttpMethods.IsHead(method) ||
           HttpMethods.IsOptions(method) ||
           HttpMethods.IsTrace(method);
}

static bool IsValidShareToken(string token)
{
    if (string.IsNullOrWhiteSpace(token) || token.Length < 3 || token.Length > 64)
    {
        return false;
    }

    foreach (var ch in token)
    {
        if (!char.IsLetterOrDigit(ch) && ch is not '-' and not '_')
        {
            return false;
        }
    }

    return true;
}

static bool IsTruthy(string? raw)
{
    var value = (raw ?? string.Empty).Trim().ToLowerInvariant();
    return value is "1" or "true" or "on" or "yes";
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

static string GuessImageContentType(string extension)
{
    return (extension ?? string.Empty).Trim().ToLowerInvariant() switch
    {
        ".png" => "image/png",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".svg" => "image/svg+xml",
        _ => "application/octet-stream"
    };
}


static string ResolvePublicBaseUrl(string? configuredValue, HttpRequest request)
{
    var configured = (configuredValue ?? string.Empty).Trim().TrimEnd('/');
    if (configured.Length > 0 && Uri.TryCreate(configured, UriKind.Absolute, out var absolute))
    {
        return absolute.GetLeftPart(UriPartial.Authority);
    }

    return $"{request.Scheme}://{request.Host}";
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

static bool IsAllowedBackgroundImageFileName(string? fileName)
{
    var extension = Path.GetExtension(fileName ?? string.Empty).ToLowerInvariant();
    return extension is ".jpg" or ".jpeg" or ".png" or ".svg" or ".webp";
}
