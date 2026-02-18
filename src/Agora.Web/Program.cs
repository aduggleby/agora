using System.Security.Claims;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Web.Auth;
using Agora.Web.Services;
using Agora.Web.Hangfire;
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
builder.Services.AddScoped<AuthEmailJob>();
builder.Services.AddScoped<EmailNotificationJob>();
builder.Services.AddSingleton<IEmailTemplateRenderer, RazorEmailTemplateRenderer>();
builder.Services.AddSingleton(new Agora.Web.Services.OgImageGenerator(
    System.IO.Path.Combine(builder.Environment.ContentRootPath, "Fonts")));

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
    db.Database.EnsureCreated();
    await EnsureSchemaUpgradesAsync(db, CancellationToken.None);
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

app.MapGet("/_legacy/login", async (HttpContext httpContext, AuthService authService, AgoraDbContext db, CancellationToken ct) =>
{
    if (httpContext.User.Identity?.IsAuthenticated == true)
    {
        return Results.Redirect("/");
    }

    var userCount = await db.Users.CountAsync(ct);
    var allowRegistration = await authService.GetAllowRegistrationAsync(ct);
    var msg = httpContext.Request.Query["msg"].ToString();

    var registerLink = userCount == 0 || allowRegistration
        ? $"""<p class="text-sm text-ink-muted mt-6 text-center">No account yet? <a href="/register" class="text-terra font-medium hover:underline">Register here</a>.</p>"""
        : $"""<p class="text-sm text-ink-muted mt-6 text-center">Registration is currently disabled.</p>""";
    var developmentLogin = isDevelopment
        ? $"""
<div class="mt-5 rounded-xl border border-border bg-cream-dark/40 p-4">
  <p class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-2">Development Login</p>
  <p class="text-sm text-ink-muted mb-3">Sign in instantly as <span class="font-medium text-ink">{AuthService.DevelopmentUserEmail}</span>.</p>
  <form method="post" action="/login/development">
    <button type="submit" class="w-full px-4 py-2 bg-ink text-white text-sm font-medium rounded-lg hover:bg-ink/90 transition-colors">Sign in as development user</button>
  </form>
</div>
"""
        : string.Empty;

    var body = $"""
<div class="max-w-sm mx-auto mt-16">
  <div class="text-center mb-8">
    <div class="inline-flex items-center justify-center w-12 h-12 bg-terra rounded-xl mb-4">
      <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
    </div>
    <h1 class="font-display text-3xl tracking-tight">Sign in</h1>
    <p class="text-ink-muted text-sm mt-1">Welcome back to Agora</p>
  </div>
  <form method="post" action="/login" class="space-y-4">
    <div>
      <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Email</label>
      <input type="email" name="email" required class="w-full px-3 py-2.5 text-sm border border-border rounded-lg bg-white focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
    </div>
    <div>
      <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Password</label>
      <input type="password" name="password" required class="w-full px-3 py-2.5 text-sm border border-border rounded-lg bg-white focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
    </div>
    <button type="submit" class="w-full px-6 py-2.5 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors">Sign in</button>
  </form>
  {developmentLogin}
  {registerLink}
</div>
""";

    return Results.Content(RenderLayout("Sign in", null, body, msg), "text/html");
});

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

app.MapGet("/_legacy/register", async (HttpContext httpContext, AuthService authService, AgoraDbContext db, CancellationToken ct) =>
{
    if (httpContext.User.Identity?.IsAuthenticated == true)
    {
        return Results.Redirect("/");
    }

    var userCount = await db.Users.CountAsync(ct);
    var allowRegistration = await authService.GetAllowRegistrationAsync(ct);
    if (userCount > 0 && !allowRegistration)
    {
        var disabledBody = """
<div class="max-w-sm mx-auto mt-16 text-center">
  <h1 class="font-display text-3xl tracking-tight">Registration disabled</h1>
  <p class="text-ink-muted text-sm mt-2">Ask an administrator to enable registrations.</p>
  <a href="/login" class="inline-block mt-6 text-sm text-terra font-medium hover:underline">Back to sign in</a>
</div>
""";
        return Results.Content(RenderLayout("Register", null, disabledBody, "Registration disabled"), "text/html");
    }

    var msg = httpContext.Request.Query["msg"].ToString();
    var body = """
<div class="max-w-sm mx-auto mt-16">
  <div class="text-center mb-8">
    <h1 class="font-display text-3xl tracking-tight">Create account</h1>
    <p class="text-ink-muted text-sm mt-1">Get started sharing files</p>
  </div>
  <form method="post" action="/register" class="space-y-4">
    <div>
      <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Email</label>
      <input type="email" name="email" required class="w-full px-3 py-2.5 text-sm border border-border rounded-lg bg-white focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
    </div>
    <div>
      <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Password</label>
      <input type="password" name="password" required class="w-full px-3 py-2.5 text-sm border border-border rounded-lg bg-white focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
    </div>
    <button type="submit" class="w-full px-6 py-2.5 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors">Register</button>
  </form>
  <p class="text-sm text-ink-muted mt-6 text-center"><a href="/login" class="text-terra font-medium hover:underline">Back to sign in</a></p>
</div>
""";

    return Results.Content(RenderLayout("Register", null, body, msg), "text/html");
});

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
            Description = "Use the button below to download your file.",
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

app.MapGet("/_legacy", async (HttpContext httpContext, ShareManager manager, CancellationToken ct) =>
{
    if (httpContext.User.Identity?.IsAuthenticated != true)
    {
        return Results.Redirect("/login");
    }

    var email = httpContext.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    var isAdmin = httpContext.User.IsInRole("admin");
    var msg = httpContext.Request.Query["msg"].ToString();
    var shares = await manager.ListRecentSharesForUploaderAsync(email, 20, ct);
    var quickDraftShareId = shares.Count == 0
        ? await manager.EnsureDraftShareAsync(email, null, ct)
        : string.Empty;
    var nowUtc = DateTime.UtcNow;
    var rows = string.Join("", shares.Select(share =>
        {
            var isExpired = share.ExpiresAtUtc is not null && share.ExpiresAtUtc <= nowUtc;
            var state = share.DeletedAtUtc is not null
                ? "Deleted"
                : isExpired
                    ? "Expired"
                    : "Active";
            var stateClass = state switch
            {
                "Active" => "bg-sage-wash text-sage",
                "Expired" => "bg-cream-dark text-ink-muted",
                _ => "bg-danger-wash text-danger"
            };
            var size = share.ZipSizeBytes >= 1024 * 1024
                ? $"{share.ZipSizeBytes / (1024.0 * 1024.0):F1} MB"
                : $"{share.ZipSizeBytes / 1024.0:F0} KB";
            var createdIso = share.CreatedAtUtc.ToString("O");
            var expiresCell = share.ExpiresAtUtc is null
                ? """<span class="text-xs text-ink-muted">Never</span>"""
                : $"""<span class="text-xs text-ink-muted" data-local-datetime="{share.ExpiresAtUtc.Value.ToString("O")}"></span>""";
            var reenableAction = isExpired
                ? $"""
<form method="post" action="/shares/{share.ShareId}/reenable" class="inline">
  <button type="submit" class="text-xs text-sage hover:underline">Re-enable 24h</button>
</form>
"""
                : string.Empty;
            return $"""
<tr class="border-b border-border/60 hover:bg-cream-dark/40 transition-colors">
  <td class="px-4 py-3 text-sm">{Html(share.ZipDisplayName)}</td>
  <td class="px-4 py-3 text-xs text-ink-muted">{share.FileCount} file(s) &middot; {size}</td>
  <td class="px-4 py-3"><span class="text-xs px-2 py-0.5 rounded-md {stateClass}">{state}</span></td>
  <td class="px-4 py-3"><span class="text-xs text-ink-muted" data-local-datetime="{createdIso}"></span></td>
  <td class="px-4 py-3">{expiresCell}</td>
  <td class="px-4 py-3 text-xs text-ink-muted">{share.DownloadCount}</td>
  <td class="px-4 py-3 text-right space-x-2">
    {reenableAction}
    <form method="post" action="/shares/{share.ShareId}/delete" data-share-delete-form data-share-name="{Html(share.ZipDisplayName)}">
      <button type="button" class="text-xs text-danger hover:underline" data-share-delete-trigger>Delete</button>
    </form>
  </td>
</tr>
""";
        }));

    var body = $"""
<section class="mb-10 rounded-2xl border border-border bg-white p-8">
  <h1 class="font-display text-5xl tracking-tight leading-tight">Fast, branded file sharing for your team.</h1>
  <p class="text-ink-muted text-sm mt-4 max-w-xl">Create expiring share links with customizable download pages, download notifications, and background processing built in.</p>
  {(shares.Count > 0
    ? """
  <div class="mt-6">
    <a href="/shares/new" class="inline-block px-5 py-2.5 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors">Share new files</a>
  </div>
"""
    : $"""
  <input type="hidden" value="{Html(quickDraftShareId)}" data-quick-share-draft-id />
  <input type="file" multiple accept="*/*" class="sr-only" data-quick-share-input />
  <div class="mt-6 rounded-lg border border-dashed border-border bg-cream p-4 cursor-pointer" data-quick-share-dropzone tabindex="0" role="button">
    <div class="flex items-center justify-between gap-3">
      <p class="text-sm text-ink-light">Drop files here or click to select files</p>
      <button type="button" class="px-3 py-1.5 bg-terra text-white text-xs font-medium rounded-md hover:bg-terra/90 transition-colors" data-quick-share-pick>Choose files</button>
    </div>
    <p class="text-xs text-ink-muted mt-2" data-quick-share-status>We'll take you to the next step as soon as your files are ready.</p>
  </div>
""")}
</section>

{(shares.Count > 0
    ? $"""
<section>
  <div class="bg-white rounded-2xl border border-border overflow-hidden">
    <div class="px-5 py-3 border-b border-border bg-cream-dark/50 flex items-center justify-between">
      <h2 class="font-display text-xl">Previous shares</h2>
      <span class="text-xs text-ink-muted">{shares.Count} shown</span>
    </div>
    <table class="w-full">
      <thead>
        <tr class="text-xs font-medium text-ink-muted uppercase tracking-wider border-b border-border">
          <th class="text-left px-4 py-2">Archive</th>
          <th class="text-left px-4 py-2">Details</th>
          <th class="text-left px-4 py-2">State</th>
          <th class="text-left px-4 py-2">Created</th>
          <th class="text-left px-4 py-2">Expires</th>
          <th class="text-left px-4 py-2">Downloads</th>
          <th class="text-right px-4 py-2">Actions</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>
"""
    : """
<section class="grid grid-cols-1 md:grid-cols-3 gap-4">
  <article class="md:col-span-2 bg-white rounded-2xl border border-border p-6">
    <p class="text-xs uppercase tracking-wider text-ink-muted">Get it done</p>
    <h3 class="font-display text-3xl tracking-tight mt-2">Send large files without the back-and-forth</h3>
    <p class="text-sm text-ink-muted mt-3">When you need to deliver files quickly, Agora gives you one simple flow: drop files, tune expiry, share the link.</p>
  </article>
  <article class="bg-white rounded-2xl border border-border p-6">
    <p class="text-xs uppercase tracking-wider text-ink-muted">Full control</p>
    <h3 class="font-display text-2xl mt-2">Host it where your data lives</h3>
    <p class="text-sm text-ink-muted mt-2">Keep files, logs, and policies on your own infrastructure so governance and retention stay in your hands.</p>
  </article>
  <article class="bg-white rounded-2xl border border-border p-6">
    <p class="text-xs uppercase tracking-wider text-ink-muted">Ease of use</p>
    <h3 class="font-display text-2xl mt-2">Simple for senders and recipients</h3>
    <p class="text-sm text-ink-muted mt-2">Your team gets a clean sharing workflow, while recipients get a clear branded page and one-click download.</p>
  </article>
  <article class="md:col-span-2 bg-white rounded-2xl border border-border p-6">
    <p class="text-xs uppercase tracking-wider text-ink-muted">Operate with confidence</p>
    <h3 class="font-display text-2xl mt-2">Automate lifecycle, keep visibility</h3>
    <p class="text-sm text-ink-muted mt-2">Expiration, cleanup, and notifications run in the background so sharing stays reliable without manual follow-up.</p>
  </article>
</section>
""")}

<dialog class="rounded-xl border border-border bg-white p-0 w-full max-w-sm backdrop:bg-black/30 m-auto" style="margin: auto;" data-share-delete-dialog>
  <form method="dialog" class="p-5">
    <h3 class="font-display text-2xl tracking-tight">Delete share?</h3>
    <p class="text-sm text-ink-muted mt-2">This removes the share immediately. File cleanup runs in the background.</p>
    <p class="text-sm text-ink-light mt-2" data-share-delete-name></p>
    <div class="mt-5 flex justify-end gap-2">
      <button type="button" class="px-4 py-2 text-sm border border-border rounded-lg bg-cream hover:bg-cream-dark/70" data-share-delete-cancel>Cancel</button>
      <button type="button" class="px-4 py-2 text-sm bg-danger text-white rounded-lg hover:bg-danger/90" data-share-delete-confirm>Delete</button>
    </div>
  </form>
</dialog>
{RenderLocalDateTimeScript()}
{RenderShareDeleteScript()}
{RenderQuickShareDropzoneScript()}
""";

    return Results.Content(RenderLayout("Agora", email, body, msg, isAdmin), "text/html");
}).RequireAuthorization();

app.MapGet("/_legacy/shares/new", async (HttpContext httpContext, AuthService authService, ShareManager manager, CancellationToken ct) =>
{
    if (httpContext.User.Identity?.IsAuthenticated != true)
    {
        return Results.Redirect("/login");
    }

    var email = httpContext.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    var isAdmin = httpContext.User.IsInRole("admin");
    var msg = httpContext.Request.Query["msg"].ToString();
    var accountDefaultNotifyMode = await authService.GetDefaultNotifyModeAsync(email, ct);
    var accountDefaultExpiryMode = await authService.GetDefaultExpiryModeAsync(email, ct);
    var requestedDraftShareId = httpContext.Request.Query["draftShareId"].ToString();
    string draftShareId;
    try
    {
        draftShareId = await manager.EnsureDraftShareAsync(email, requestedDraftShareId, ct);
    }
    catch
    {
        draftShareId = await manager.EnsureDraftShareAsync(email, null, ct);
    }

    var draftTemplate = await manager.GetDraftTemplateAsync(email, draftShareId, ct);
    var stagedUploads = await manager.ListStagedUploadsForDraftAsync(email, draftShareId, ct);
    var templateModeForDraft = string.Equals(draftTemplate.TemplateMode, "per_upload", StringComparison.OrdinalIgnoreCase)
        ? "per_upload"
        : "account_default";
    var accountDefaultNotifyModeLabel = accountDefaultNotifyMode switch
    {
        "none" => "None",
        "every_time" => "Every download",
        _ => "First download only"
    };
    var accountDefaultExpiryModeLabel = accountDefaultExpiryMode switch
    {
        "1_hour" => "1 hour",
        "24_hours" => "24 hours",
        "30_days" => "30 days",
        "1_year" => "1 year",
        "indefinite" => "Indefinite",
        _ => "7 days"
    };

    var body = RenderCreateSharePageBody(
        draftShareId,
        draftTemplate,
        stagedUploads,
        templateModeForDraft,
        accountDefaultNotifyModeLabel,
        accountDefaultExpiryModeLabel,
        accountDefaultExpiryMode);

    return Results.Content(RenderLayout("Share files", email, body, msg, isAdmin), "text/html");
}).RequireAuthorization();

app.MapGet("/_legacy/account/landing-page-designer", async (HttpContext httpContext, ShareManager manager, CancellationToken ct) =>
{
    if (httpContext.User.Identity?.IsAuthenticated != true)
    {
        return Results.Redirect("/login");
    }

    var email = httpContext.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Redirect("/login");
    }

    var isAdmin = httpContext.User.IsInRole("admin");
    var msg = httpContext.Request.Query["msg"].ToString();
    var template = await manager.GetAccountTemplateAsync(email, ct);
    var body = RenderAccountLandingPageDesignerBody(template);
    return Results.Content(RenderLayout("Download Page Settings", email, body, msg, isAdmin), "text/html");
}).RequireAuthorization();

app.MapGet("/_legacy/account/settings", async (HttpContext httpContext, AuthService authService, CancellationToken ct) =>
{
    if (httpContext.User.Identity?.IsAuthenticated != true)
    {
        return Results.Redirect("/login");
    }

    var email = httpContext.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Redirect("/login");
    }

    var isAdmin = httpContext.User.IsInRole("admin");
    var msg = httpContext.Request.Query["msg"].ToString();
    var accountDefaultNotifyMode = await authService.GetDefaultNotifyModeAsync(email, ct);
    var accountDefaultExpiryMode = await authService.GetDefaultExpiryModeAsync(email, ct);
    var body = RenderAccountSettingsBody(accountDefaultNotifyMode, accountDefaultExpiryMode);
    return Results.Content(RenderLayout("Account Settings", email, body, msg, isAdmin), "text/html");
}).RequireAuthorization();

app.MapGet("/_legacy/share/landing-page-designer", async (HttpContext httpContext, ShareManager manager, CancellationToken ct) =>
{
    if (httpContext.User.Identity?.IsAuthenticated != true)
    {
        return Results.Redirect("/login");
    }

    var email = httpContext.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(email))
    {
        return Results.Redirect("/login");
    }

    var requestedDraftShareId = httpContext.Request.Query["draftShareId"].ToString();
    string draftShareId;
    try
    {
        draftShareId = await manager.EnsureDraftShareAsync(email, requestedDraftShareId, ct);
    }
    catch
    {
        return Results.Redirect("/shares/new?msg=Unable%20to%20open%20share%20designer");
    }

    var draftTemplate = await manager.GetDraftTemplateAsync(email, draftShareId, ct);
    var isAdmin = httpContext.User.IsInRole("admin");
    var msg = httpContext.Request.Query["msg"].ToString();
    var body = RenderShareLandingPageDesignerBody(draftShareId, draftTemplate);
    return Results.Content(RenderLayout("Share Download Page Designer", email, body, msg, isAdmin), "text/html");
}).RequireAuthorization();

app.MapGet("/_legacy/admin", async (HttpContext httpContext, AuthService authService, CancellationToken ct) =>
{
    var currentUserEmail = httpContext.User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
    var currentUserId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
    var users = await authService.GetUsersAsync(ct);
    var allowRegistration = await authService.GetAllowRegistrationAsync(ct);
    var msg = httpContext.Request.Query["msg"].ToString();

    var rows = string.Join("", users.Select(user =>
    {
        var id = user.Id.ToString();
        var statusDot = user.IsEnabled
            ? """<span class="inline-block w-2 h-2 rounded-full bg-sage"></span>"""
            : """<span class="inline-block w-2 h-2 rounded-full bg-ink-muted"></span>""";

        var roleForm = user.Id.ToString().Equals(currentUserId, StringComparison.OrdinalIgnoreCase)
            ? """<span class="text-xs text-ink-muted">(current user)</span>"""
            : $"""
<form method="post" action="/admin/users/{id}/role" class="inline-flex items-center gap-1">
  <select name="role" class="text-xs px-2 py-1 border border-border rounded-md bg-cream focus:outline-none focus:border-terra">
    <option value="user" {(user.Role == "user" ? "selected" : "")}>user</option>
    <option value="admin" {(user.Role == "admin" ? "selected" : "")}>admin</option>
  </select>
  <button type="submit" class="text-xs text-terra hover:underline">Change</button>
</form>
""";

        var toggleForm = $"""
<form method="post" action="/admin/users/{id}/enabled" class="inline">
  <input type="hidden" name="enabled" value="{(!user.IsEnabled).ToString().ToLowerInvariant()}" />
  <button type="submit" class="text-xs {(user.IsEnabled ? "text-ink-muted hover:text-danger" : "text-sage hover:underline")}">{(user.IsEnabled ? "Disable" : "Enable")}</button>
</form>
""";

        var deleteForm = user.Email == currentUserEmail
            ? """
<span class="text-xs text-ink-muted">(you)</span>
"""
            : $"""
<form method="post" action="/admin/users/{id}/delete" onsubmit="return confirm('Delete this user?');" class="inline">
  <button type="submit" class="text-xs text-danger hover:underline">Delete</button>
</form>
""";

        return $"""
<tr class="border-b border-border/60 hover:bg-cream-dark/50 transition-colors">
  <td class="px-4 py-3 text-sm">{statusDot} {Html(user.Email)}</td>
  <td class="px-4 py-3"><span class="text-xs bg-cream-dark text-ink-muted px-2 py-0.5 rounded-md">{Html(user.Role)}</span></td>
  <td class="px-4 py-3">{roleForm}</td>
  <td class="px-4 py-3">{toggleForm}</td>
  <td class="px-4 py-3">{deleteForm}</td>
</tr>
""";
    }));

    var body = $"""
<section class="mb-8">
  <h2 class="font-display text-3xl tracking-tight">Manage users</h2>
  <p class="text-ink-muted text-sm mt-1">Manage users and registration policy.</p>
</section>

<section class="mb-8">
  <div class="bg-white rounded-2xl border border-border p-6">
    <div class="flex items-center justify-between mb-4">
      <h3 class="font-display text-xl">Registration policy</h3>
      <span class="text-xs bg-{(allowRegistration ? "sage-wash text-sage" : "cream-dark text-ink-muted")} px-2 py-0.5 rounded-md">{(allowRegistration ? "Open" : "Closed")}</span>
    </div>
    <form method="post" action="/admin/settings/registration">
      <label class="inline-flex items-center gap-3 cursor-pointer select-none">
        <input type="hidden" name="enabled" value="false" />
        <input type="checkbox" name="enabled" value="true" {(allowRegistration ? "checked" : string.Empty)} class="peer sr-only" onchange="this.form.submit()" />
        <span class="relative w-11 h-6 rounded-full bg-ink-muted/40 transition-colors peer-checked:bg-sage">
          <span class="absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white transition-transform peer-checked:translate-x-5"></span>
        </span>
        <span class="text-sm text-ink-light">Allow new user registration</span>
      </label>
    </form>
  </div>
</section>

<section>
  <div class="bg-white rounded-2xl border border-border overflow-hidden">
    <div class="px-5 py-3 border-b border-border bg-cream-dark/50 flex items-center justify-between">
      <h3 class="font-display text-lg">Users</h3>
      <span class="text-xs text-ink-muted">{users.Count} total</span>
    </div>
    <table class="w-full">
      <thead>
        <tr class="text-xs font-medium text-ink-muted uppercase tracking-wider border-b border-border">
          <th class="text-left px-4 py-2">Email</th>
          <th class="text-left px-4 py-2">Role</th>
          <th class="text-left px-4 py-2">Change role</th>
          <th class="text-left px-4 py-2">Status</th>
          <th class="text-left px-4 py-2">Delete</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>
""";

    return Results.Content(RenderLayout("Manage users", currentUserEmail, body, msg, true), "text/html");
}).RequireAuthorization("AdminOnly");

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

app.MapPost("/api/shares", async (HttpContext context, ShareManager manager, AuthService authService, IOptions<AgoraOptions> options, HttpRequest request, CancellationToken ct) =>
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

    var expiryMode = expiryModeRaw == "indefinite" ? ExpiryMode.Indefinite : ExpiryMode.Date;
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

    var templateModeRaw = form["templateMode"].ToString();
    var templateMode = string.Equals(templateModeRaw, "per_upload", StringComparison.OrdinalIgnoreCase)
        ? TemplateMode.PerUpload
        : TemplateMode.AccountDefault;

    UploadSourceFile? templateBackgroundFile = null;
    var templateBackgroundUploadId = form["template.backgroundUploadId"].ToString().Trim();
    if (!string.IsNullOrWhiteSpace(templateBackgroundUploadId))
    {
        IReadOnlyList<ShareManager.StagedUploadFile> stagedTemplateBackground;
        try
        {
            stagedTemplateBackground = await manager.ResolveStagedUploadsAsync(uploaderEmail, [templateBackgroundUploadId], draftShareId, ct);
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(ex.Message);
        }

        var stagedBackground = stagedTemplateBackground.SingleOrDefault();
        if (stagedBackground is not null)
        {
            templateBackgroundFile = new UploadSourceFile(
                TempPath: stagedBackground.TempPath,
                OriginalFileName: stagedBackground.OriginalFileName,
                OriginalSizeBytes: stagedBackground.OriginalSizeBytes,
                ContentType: stagedBackground.ContentType);
        }
    }

    var tempRoot = Path.Combine(cfg.StorageRoot, "uploads", "tmp", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(tempRoot);

    var uploadFiles = new List<UploadSourceFile>(files.Count + stagedUploads.Count);
    var stagedDirectoriesToDelete = new List<string>(stagedUploads.Count + 1);
    var shareCreated = false;

    try
    {
        foreach (var staged in stagedUploads)
        {
            uploadFiles.Add(new UploadSourceFile(
                TempPath: staged.TempPath,
                OriginalFileName: staged.OriginalFileName,
                OriginalSizeBytes: staged.OriginalSizeBytes,
                ContentType: staged.ContentType));
            stagedDirectoriesToDelete.Add(staged.DirectoryPath);
        }

        if (templateBackgroundFile is not null && !string.IsNullOrWhiteSpace(templateBackgroundUploadId))
        {
            var stagedTemplateBackground = await manager.ResolveStagedUploadsAsync(uploaderEmail, [templateBackgroundUploadId], draftShareId, ct);
            var stagedBackgroundFile = stagedTemplateBackground.SingleOrDefault();
            if (stagedBackgroundFile is not null && !stagedDirectoriesToDelete.Contains(stagedBackgroundFile.DirectoryPath, StringComparer.Ordinal))
            {
                stagedDirectoriesToDelete.Add(stagedBackgroundFile.DirectoryPath);
            }
        }

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
            ShareToken = shareToken,
            Message = form["message"].ToString(),
            DownloadPassword = downloadPassword,
            ZipFileName = form["zipFileName"].ToString(),
            ExpiryMode = expiryMode,
            ExpiresAtUtc = expiresAtUtc,
            NotifyMode = notifyMode,
            TemplateMode = templateMode,
            TemplateTitle = form["template.title"].ToString(),
            TemplateH1 = form["template.h1"].ToString(),
            TemplateDescription = form["template.description"].ToString(),
            TemplateBackgroundImageUrl = string.Empty,
            TemplateBackgroundColorHex = NormalizeHexColor(form["template.backgroundColorHex"].ToString()),
            TemplateContainerPosition = NormalizeContainerPosition(form["template.containerPosition"].ToString()),
            TemplateBackgroundFile = templateBackgroundFile,
            Files = uploadFiles
        };

        CreateShareResult result;
        try
        {
            result = await manager.CreateShareAsync(command, ct);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("already in use", StringComparison.OrdinalIgnoreCase))
        {
            var suggestedShareToken = await manager.GenerateUniqueShareTokenAsync(8, ct);
            return Results.Redirect($"/shares/new?draftShareId={Uri.EscapeDataString(draftShareId)}&shareToken={Uri.EscapeDataString(shareToken)}&suggestedShareToken={Uri.EscapeDataString(suggestedShareToken)}&msg=That%20share%20link%20is%20already%20in%20use");
        }

        shareCreated = true;
        await manager.DeleteDraftShareAsync(uploaderEmail, draftShareId, ct);
        return Results.Redirect($"/shares/created?token={Uri.EscapeDataString(result.Token)}");
    }
    finally
    {
        if (shareCreated)
        {
            foreach (var directoryPath in stagedDirectoriesToDelete)
            {
                if (Directory.Exists(directoryPath))
                {
                    Directory.Delete(directoryPath, recursive: true);
                }
            }
        }

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

app.MapGet("/_legacy/s/{token}", async (ShareManager manager, string token, CancellationToken ct) =>
{
    var share = await manager.FindByTokenAsync(token, ct);
    if (share is null)
    {
        return Results.NotFound("Share not found.");
    }

    var isExpired = ShareManager.IsExpired(share, DateTime.UtcNow);

    var messageHtml = string.IsNullOrWhiteSpace(share.UploaderMessage)
        ? string.Empty
        : $"""<p class="text-sm text-ink-light mt-4 p-3 bg-cream-dark rounded-lg"><span class="font-medium text-ink">Message:</span> {Html(share.UploaderMessage)}</p>""";
    var expiredHtml = isExpired
        ? """<p style="color:#7a3f20;font-size:0.875rem;margin-top:1rem;padding:0.75rem;border-radius:0.5rem;background:#f6e5dc;border:1px solid #e8c8b5;">This link has expired.</p>"""
        : string.Empty;
    var downloadButtonHtml = isExpired
        ? """<button type="button" class="btn" style="opacity:.6;cursor:not-allowed;" disabled title="This link has expired.">Download</button>"""
        : string.IsNullOrWhiteSpace(share.DownloadPasswordHash)
            ? $"""<a href="/s/{token}/download" class="btn">Download</a>"""
            : $"""<p style="color:#5C534A;font-size:0.8125rem;line-height:1.4;">This share is password-protected. Open <a href="/s/{token}" style="color:#C4663A;text-decoration:underline;">the current download page</a> to enter the password.</p>""";

    var backgroundImageUrl = ResolveLandingBackgroundUrl(share.BackgroundImageUrl, token);
    var backgroundColor = NormalizeHexColor(share.PageBackgroundColorHex);
    var bgStyle = string.IsNullOrWhiteSpace(backgroundImageUrl)
        ? string.Empty
        : $"background-image:url({Html(backgroundImageUrl)});background-size:cover;background-position:center;";
    var bgColorStyle = string.IsNullOrWhiteSpace(backgroundColor)
        ? string.Empty
        : $"background-color:{backgroundColor};";

    var sizeDisplay = share.ZipSizeBytes >= 1024 * 1024
        ? $"{share.ZipSizeBytes / (1024.0 * 1024.0):F1} MB"
        : $"{share.ZipSizeBytes / 1024.0:F0} KB";

    var html = $$"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>File Download</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600&family=Instrument+Serif:ital@0;1&display=swap" rel="stylesheet">
  <style>
    :root {
      --cream: #FAF7F2;
      --ink: #1A1614;
      --ink-light: #5C534A;
      --ink-muted: #9B9189;
      --terra: #C4663A;
      --border: #E5DFD7;
      --cream-dark: #F0EBE3;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'DM Sans', sans-serif;
      background: var(--cream);
      color: var(--ink);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem;
      {{bgColorStyle}}
      {{bgStyle}}
    }
    .card {
      background: white;
      border-radius: 1rem;
      padding: 2.5rem;
      max-width: 480px;
      width: 100%;
      box-shadow: 0 8px 30px rgba(26, 22, 20, 0.08);
    }
    .font-display { font-family: 'Instrument Serif', serif; }
    .btn {
      display: inline-block;
      width: 100%;
      padding: 0.75rem 1.5rem;
      background: var(--terra);
      color: white;
      border: none;
      border-radius: 0.5rem;
      font-size: 0.875rem;
      font-weight: 500;
      text-align: center;
      text-decoration: none;
      cursor: pointer;
      transition: background 0.15s;
    }
    .btn:hover { background: #B55A30; }
  </style>
</head>
<body>
  <div class="card">
    <h1 class="font-display" style="font-size:1.75rem;letter-spacing:-0.01em;">{{Html(share.PageH1)}}</h1>
    <p style="color:var(--ink-light);font-size:0.875rem;margin-top:0.5rem;">{{Html(share.PageDescription)}}</p>

    <div style="margin-top:1.5rem;padding:1rem;background:var(--cream);border-radius:0.75rem;border:1px solid var(--border);">
      <div style="display:flex;align-items:center;gap:0.75rem;">
        <svg style="width:1.5rem;height:1.5rem;color:var(--terra);flex-shrink:0;" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"/></svg>
        <div>
          <p style="font-weight:500;font-size:0.875rem;">{{Html(share.ZipDisplayName)}}</p>
          <p style="color:var(--ink-muted);font-size:0.75rem;">{{share.Files.Count}} {{(share.Files.Count == 1 ? "file" : "files")}} &middot; {{sizeDisplay}}</p>
        </div>
      </div>
    </div>

    {{messageHtml}}
    {{expiredHtml}}

    <div style="margin-top:1.5rem;">
      {{downloadButtonHtml}}
    </div>

    <p style="color:var(--ink-muted);font-size:0.6875rem;margin-top:1.5rem;text-align:center;">Shared via Agora</p>
  </div>
</body>
</html>
""";

    return Results.Content(html, "text/html");
});

app.MapGet("/s/{token}/background", async (ShareManager manager, IOptions<AgoraOptions> options, string token, ILoggerFactory loggerFactory, CancellationToken ct) =>
{
    var logger = loggerFactory.CreateLogger("Agora.DownloadPageBackground");
    var share = await manager.FindByTokenAsync(token, ct);
    if (share is null)
    {
        logger.LogWarning("Background request for token {Token} failed: share not found.", token);
        return Results.NotFound();
    }

    if (ShareManager.IsExpired(share, DateTime.UtcNow))
    {
        logger.LogInformation("Background request for token {Token} denied: share expired or deleted.", token);
        return Results.StatusCode(StatusCodes.Status410Gone);
    }

    var marker = share.BackgroundImageUrl ?? string.Empty;
    if (!marker.StartsWith("internal:", StringComparison.OrdinalIgnoreCase))
    {
        logger.LogInformation(
            "Background request for token {Token} failed: share has no internal marker. Marker: {Marker}",
            token,
            marker.Length == 0 ? "<empty>" : marker);
        return Results.NotFound();
    }

    var relativePath = marker["internal:".Length..].TrimStart('/', '\\');
    var storageRoot = Path.GetFullPath(options.Value.StorageRoot);
    var absolutePath = Path.GetFullPath(Path.Combine(storageRoot, relativePath));
    if (!absolutePath.StartsWith(storageRoot, StringComparison.Ordinal))
    {
        logger.LogWarning(
            "Background request for token {Token} failed: resolved path escaped storage root. Marker: {Marker}",
            token,
            marker);
        return Results.NotFound();
    }

    if (!File.Exists(absolutePath))
    {
        logger.LogWarning(
            "Background request for token {Token} failed: file missing at {Path}. Marker: {Marker}",
            token,
            absolutePath,
            marker);
        return Results.NotFound();
    }

    logger.LogInformation(
        "Background request for token {Token} served file {Path}. Marker: {Marker}",
        token,
        absolutePath,
        marker);
    return Results.File(absolutePath, GuessImageContentType(Path.GetExtension(absolutePath)));
});

app.MapGet("/s/{token}/og-image", async (
    ShareManager manager,
    IOptions<AgoraOptions> options,
    Agora.Web.Services.OgImageGenerator ogGenerator,
    string token,
    CancellationToken ct) =>
{
    var share = await manager.FindByTokenAsync(token, ct);
    if (share is null) return Results.NotFound();

    // Resolve background image path for the generator
    string? bgPath = null;
    var marker = share.BackgroundImageUrl ?? string.Empty;
    if (marker.StartsWith("internal:", StringComparison.OrdinalIgnoreCase))
    {
        var relativePath = marker["internal:".Length..].TrimStart('/', '\\');
        var storageRoot = Path.GetFullPath(options.Value.StorageRoot);
        var absolutePath = Path.GetFullPath(Path.Combine(storageRoot, relativePath));
        if (absolutePath.StartsWith(storageRoot, StringComparison.Ordinal) && File.Exists(absolutePath))
        {
            bgPath = absolutePath;
        }
    }

    var isExpired = ShareManager.IsExpired(share, DateTime.UtcNow);
    var sizeDisplay = share.ZipSizeBytes >= 1024 * 1024
        ? $"{share.ZipSizeBytes / (1024.0 * 1024.0):F1} MB"
        : $"{share.ZipSizeBytes / 1024.0:F0} KB";

    var imageBytes = await ogGenerator.GenerateShareOgImageAsync(
        backgroundImagePath: bgPath,
        backgroundColorHex: share.PageBackgroundColorHex,
        title: share.PageH1,
        subtitle: share.PageTitle,
        fileName: share.ZipDisplayName,
        fileCount: share.Files.Count,
        sizeDisplay: sizeDisplay,
        isExpired: isExpired);

    return Results.File(imageBytes, "image/png");
});

app.MapGet("/s/{token}/download", (string token) =>
{
    // Avoid recording speculative GET/HEAD requests as real downloads.
    return Results.Redirect($"/s/{token}");
}).RequireRateLimiting("DownloadEndpoints");

app.MapPost("/s/{token}/download", async (ShareManager manager, IOptions<AgoraOptions> options, string token, HttpRequest request, CancellationToken ct) =>
{
    var share = await manager.FindByTokenAsync(token, ct);
    if (share is null)
    {
        return Results.NotFound();
    }

    if (ShareManager.IsExpired(share, DateTime.UtcNow))
    {
        return Results.Redirect($"/s/{token}");
    }

    var absolutePath = Path.Combine(options.Value.StorageRoot, share.ZipDiskPath);
    if (!File.Exists(absolutePath))
    {
        return Results.StatusCode(StatusCodes.Status410Gone);
    }

    var requiresPassword = !string.IsNullOrWhiteSpace(share.DownloadPasswordHash);
    if (requiresPassword)
    {
        var form = request.HasFormContentType
            ? await request.ReadFormAsync(ct)
            : null;
        var downloadPassword = form?["downloadPassword"].ToString() ?? string.Empty;

        if (string.IsNullOrWhiteSpace(downloadPassword))
        {
            return Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=password_required");
        }

        var passwordHash = share.DownloadPasswordHash ?? string.Empty;
        if (!PasswordHasher.Verify(downloadPassword, passwordHash))
        {
            return Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=invalid_password");
        }

        var tempRoot = Path.Combine(options.Value.StorageRoot, "downloads", "tmp");
        Directory.CreateDirectory(tempRoot);
        var decryptedPath = Path.Combine(tempRoot, $"{Guid.NewGuid():N}.zip");

        try
        {
            await ZipEncryption.DecryptFileAsync(absolutePath, decryptedPath, downloadPassword, ct);
        }
        catch (CryptographicException)
        {
            if (File.Exists(decryptedPath))
            {
                File.Delete(decryptedPath);
            }

            return Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=invalid_password");
        }

        var isAuthenticated = request.HttpContext.User.Identity?.IsAuthenticated == true;
        if (!isAuthenticated)
        {
            var ip = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var userAgent = request.Headers.UserAgent.ToString();
            await manager.RecordDownloadAsync(share, token, ip, userAgent, ct);
        }

        var decryptedStream = File.OpenRead(decryptedPath);
        request.HttpContext.Response.OnCompleted(() =>
        {
            try
            {
                decryptedStream.Dispose();
                if (File.Exists(decryptedPath))
                {
                    File.Delete(decryptedPath);
                }
            }
            catch
            {
                // Best effort cleanup for temporary decrypted files.
            }

            return Task.CompletedTask;
        });

        return Results.File(decryptedStream, "application/zip", share.ZipDisplayName);
    }

    var isAuthenticatedRequester = request.HttpContext.User.Identity?.IsAuthenticated == true;
    if (!isAuthenticatedRequester)
    {
        var ip = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = request.Headers.UserAgent.ToString();
        await manager.RecordDownloadAsync(share, token, ip, userAgent, ct);
    }

    var stream = File.OpenRead(absolutePath);
    return Results.File(stream, "application/zip", share.ZipDisplayName);
}).RequireRateLimiting("DownloadEndpoints");

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

static bool TryNormalizeOptionalSharePassword(string? raw, out string? password)
{
    password = string.IsNullOrWhiteSpace(raw) ? null : raw.Trim();
    if (password is null)
    {
        return true;
    }

    return password.Length >= 8 && password.Length <= 256;
}

static async Task EnsureSchemaUpgradesAsync(AgoraDbContext db, CancellationToken cancellationToken)
{
    if (db.Database.IsSqlite())
    {
        var hasDefaultNotifyMode = await SqliteColumnExistsAsync(db, "Users", "DefaultNotifyMode", cancellationToken);
        if (!hasDefaultNotifyMode)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "DefaultNotifyMode" TEXT NOT NULL DEFAULT 'once'""",
                cancellationToken);
        }

        var hasDefaultExpiryMode = await SqliteColumnExistsAsync(db, "Users", "DefaultExpiryMode", cancellationToken);
        if (!hasDefaultExpiryMode)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "DefaultExpiryMode" TEXT NOT NULL DEFAULT '7_days'""",
                cancellationToken);
        }

        var hasFailedLoginCount = await SqliteColumnExistsAsync(db, "Users", "FailedLoginCount", cancellationToken);
        if (!hasFailedLoginCount)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "FailedLoginCount" INTEGER NOT NULL DEFAULT 0""",
                cancellationToken);
        }

        var hasLastFailedLoginAtUtc = await SqliteColumnExistsAsync(db, "Users", "LastFailedLoginAtUtc", cancellationToken);
        if (!hasLastFailedLoginAtUtc)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "LastFailedLoginAtUtc" TEXT NULL""",
                cancellationToken);
        }

        var hasLockoutEndUtc = await SqliteColumnExistsAsync(db, "Users", "LockoutEndUtc", cancellationToken);
        if (!hasLockoutEndUtc)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "LockoutEndUtc" TEXT NULL""",
                cancellationToken);
        }

        var hasEmailConfirmed = await SqliteColumnExistsAsync(db, "Users", "EmailConfirmed", cancellationToken);
        if (!hasEmailConfirmed)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "EmailConfirmed" INTEGER NOT NULL DEFAULT 1""",
                cancellationToken);
        }

        var hasEmailConfirmedAtUtc = await SqliteColumnExistsAsync(db, "Users", "EmailConfirmedAtUtc", cancellationToken);
        if (!hasEmailConfirmedAtUtc)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "EmailConfirmedAtUtc" TEXT NULL""",
                cancellationToken);
        }

        var hasEmailConfirmationTokenHash = await SqliteColumnExistsAsync(db, "Users", "EmailConfirmationTokenHash", cancellationToken);
        if (!hasEmailConfirmationTokenHash)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "EmailConfirmationTokenHash" TEXT NULL""",
                cancellationToken);
        }

        var hasEmailConfirmationTokenExpiresAtUtc = await SqliteColumnExistsAsync(db, "Users", "EmailConfirmationTokenExpiresAtUtc", cancellationToken);
        if (!hasEmailConfirmationTokenExpiresAtUtc)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "EmailConfirmationTokenExpiresAtUtc" TEXT NULL""",
                cancellationToken);
        }

        var hasPendingEmail = await SqliteColumnExistsAsync(db, "Users", "PendingEmail", cancellationToken);
        if (!hasPendingEmail)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "PendingEmail" TEXT NULL""",
                cancellationToken);
        }

        var hasPendingEmailTokenHash = await SqliteColumnExistsAsync(db, "Users", "PendingEmailTokenHash", cancellationToken);
        if (!hasPendingEmailTokenHash)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "PendingEmailTokenHash" TEXT NULL""",
                cancellationToken);
        }

        var hasPendingEmailTokenExpiresAtUtc = await SqliteColumnExistsAsync(db, "Users", "PendingEmailTokenExpiresAtUtc", cancellationToken);
        if (!hasPendingEmailTokenExpiresAtUtc)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "PendingEmailTokenExpiresAtUtc" TEXT NULL""",
                cancellationToken);
        }

        var hasPendingPasswordHash = await SqliteColumnExistsAsync(db, "Users", "PendingPasswordHash", cancellationToken);
        if (!hasPendingPasswordHash)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "PendingPasswordHash" TEXT NULL""",
                cancellationToken);
        }

        var hasPendingPasswordTokenHash = await SqliteColumnExistsAsync(db, "Users", "PendingPasswordTokenHash", cancellationToken);
        if (!hasPendingPasswordTokenHash)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "PendingPasswordTokenHash" TEXT NULL""",
                cancellationToken);
        }

        var hasPendingPasswordTokenExpiresAtUtc = await SqliteColumnExistsAsync(db, "Users", "PendingPasswordTokenExpiresAtUtc", cancellationToken);
        if (!hasPendingPasswordTokenExpiresAtUtc)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "PendingPasswordTokenExpiresAtUtc" TEXT NULL""",
                cancellationToken);
        }

        var hasPasswordResetTokenHash = await SqliteColumnExistsAsync(db, "Users", "PasswordResetTokenHash", cancellationToken);
        if (!hasPasswordResetTokenHash)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "PasswordResetTokenHash" TEXT NULL""",
                cancellationToken);
        }

        var hasPasswordResetTokenExpiresAtUtc = await SqliteColumnExistsAsync(db, "Users", "PasswordResetTokenExpiresAtUtc", cancellationToken);
        if (!hasPasswordResetTokenExpiresAtUtc)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Users" ADD COLUMN "PasswordResetTokenExpiresAtUtc" TEXT NULL""",
                cancellationToken);
        }

        var hasAccountTemplateBackgroundColor = await SqliteColumnExistsAsync(db, "AccountTemplates", "BackgroundColorHex", cancellationToken);
        if (!hasAccountTemplateBackgroundColor)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "AccountTemplates" ADD COLUMN "BackgroundColorHex" TEXT NULL""",
                cancellationToken);
        }

        var hasAccountTemplateContainerPosition = await SqliteColumnExistsAsync(db, "AccountTemplates", "ContainerPosition", cancellationToken);
        if (!hasAccountTemplateContainerPosition)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "AccountTemplates" ADD COLUMN "ContainerPosition" TEXT NOT NULL DEFAULT 'center'""",
                cancellationToken);
        }

        var hasShareBackgroundColor = await SqliteColumnExistsAsync(db, "Shares", "PageBackgroundColorHex", cancellationToken);
        if (!hasShareBackgroundColor)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Shares" ADD COLUMN "PageBackgroundColorHex" TEXT NULL""",
                cancellationToken);
        }

        var hasShareContainerPosition = await SqliteColumnExistsAsync(db, "Shares", "PageContainerPosition", cancellationToken);
        if (!hasShareContainerPosition)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Shares" ADD COLUMN "PageContainerPosition" TEXT NOT NULL DEFAULT 'center'""",
                cancellationToken);
        }

        var hasShareToken = await SqliteColumnExistsAsync(db, "Shares", "ShareToken", cancellationToken);
        if (!hasShareToken)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Shares" ADD COLUMN "ShareToken" TEXT NOT NULL DEFAULT ''""",
                cancellationToken);
        }

        var hasShareDownloadPasswordHash = await SqliteColumnExistsAsync(db, "Shares", "DownloadPasswordHash", cancellationToken);
        if (!hasShareDownloadPasswordHash)
        {
            await db.Database.ExecuteSqlRawAsync(
                """ALTER TABLE "Shares" ADD COLUMN "DownloadPasswordHash" TEXT NULL""",
                cancellationToken);
        }
    }
    else if (db.Database.IsSqlServer())
    {
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'DefaultNotifyMode') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [DefaultNotifyMode] nvarchar(20) NOT NULL CONSTRAINT [DF_Users_DefaultNotifyMode] DEFAULT 'once'
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'DefaultExpiryMode') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [DefaultExpiryMode] nvarchar(20) NOT NULL CONSTRAINT [DF_Users_DefaultExpiryMode] DEFAULT '7_days'
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'FailedLoginCount') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [FailedLoginCount] int NOT NULL CONSTRAINT [DF_Users_FailedLoginCount] DEFAULT 0
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'LastFailedLoginAtUtc') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [LastFailedLoginAtUtc] datetime2 NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'LockoutEndUtc') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [LockoutEndUtc] datetime2 NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'EmailConfirmed') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [EmailConfirmed] bit NOT NULL CONSTRAINT [DF_Users_EmailConfirmed] DEFAULT 1
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'EmailConfirmedAtUtc') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [EmailConfirmedAtUtc] datetime2 NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'EmailConfirmationTokenHash') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [EmailConfirmationTokenHash] nvarchar(64) NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'EmailConfirmationTokenExpiresAtUtc') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [EmailConfirmationTokenExpiresAtUtc] datetime2 NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'PendingEmail') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [PendingEmail] nvarchar(320) NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'PendingEmailTokenHash') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [PendingEmailTokenHash] nvarchar(64) NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'PendingEmailTokenExpiresAtUtc') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [PendingEmailTokenExpiresAtUtc] datetime2 NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'PendingPasswordHash') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [PendingPasswordHash] nvarchar(1000) NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'PendingPasswordTokenHash') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [PendingPasswordTokenHash] nvarchar(64) NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'PendingPasswordTokenExpiresAtUtc') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [PendingPasswordTokenExpiresAtUtc] datetime2 NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'PasswordResetTokenHash') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [PasswordResetTokenHash] nvarchar(64) NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Users', 'PasswordResetTokenExpiresAtUtc') IS NULL
            BEGIN
              ALTER TABLE [Users] ADD [PasswordResetTokenExpiresAtUtc] datetime2 NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('AccountTemplates', 'BackgroundColorHex') IS NULL
            BEGIN
              ALTER TABLE [AccountTemplates] ADD [BackgroundColorHex] nvarchar(16) NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('AccountTemplates', 'ContainerPosition') IS NULL
            BEGIN
              ALTER TABLE [AccountTemplates] ADD [ContainerPosition] nvarchar(32) NOT NULL CONSTRAINT [DF_AccountTemplates_ContainerPosition] DEFAULT 'center'
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Shares', 'PageBackgroundColorHex') IS NULL
            BEGIN
              ALTER TABLE [Shares] ADD [PageBackgroundColorHex] nvarchar(16) NULL
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Shares', 'PageContainerPosition') IS NULL
            BEGIN
              ALTER TABLE [Shares] ADD [PageContainerPosition] nvarchar(32) NOT NULL CONSTRAINT [DF_Shares_PageContainerPosition] DEFAULT 'center'
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Shares', 'ShareToken') IS NULL
            BEGIN
              ALTER TABLE [Shares] ADD [ShareToken] nvarchar(120) NOT NULL CONSTRAINT [DF_Shares_ShareToken] DEFAULT ''
            END
            """,
            cancellationToken);
        await db.Database.ExecuteSqlRawAsync(
            """
            IF COL_LENGTH('Shares', 'DownloadPasswordHash') IS NULL
            BEGIN
              ALTER TABLE [Shares] ADD [DownloadPasswordHash] nvarchar(1000) NULL
            END
            """,
            cancellationToken);
    }
}

static async Task<bool> SqliteColumnExistsAsync(AgoraDbContext db, string tableName, string columnName, CancellationToken cancellationToken)
{
    var connection = db.Database.GetDbConnection();
    var openedHere = false;
    if (connection.State != ConnectionState.Open)
    {
        await connection.OpenAsync(cancellationToken);
        openedHere = true;
    }

    try
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM pragma_table_info('{tableName}') WHERE name = @columnName";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "@columnName";
        parameter.Value = columnName;
        command.Parameters.Add(parameter);
        var result = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result) > 0;
    }
    finally
    {
        if (openedHere)
        {
            await connection.CloseAsync();
        }
    }
}

static string ResolveLandingBackgroundUrl(string? value, string token)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return string.Empty;
    }

    return value.StartsWith("internal:", StringComparison.OrdinalIgnoreCase)
        ? $"/s/{token}/background"
        : value;
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

static string RenderCreateSharePageBody(
    string draftShareId,
    ShareManager.DraftTemplateState draftTemplate,
    IReadOnlyList<ShareManager.StagedUploadFile> stagedUploads,
    string templateModeForDraft,
    string accountDefaultNotifyModeLabel,
    string accountDefaultExpiryModeLabel,
    string accountDefaultExpiryMode) => $"""
<section class="mb-10">
  <h2 class="font-display text-4xl tracking-tight mb-1">Share files</h2>
  <p class="text-ink-muted text-sm mt-3 max-w-md">Upload files, tune options, and generate a share link.</p>
</section>

<section class="mb-10">
  <div class="bg-white rounded-2xl border border-border p-6">
    <form action="/api/shares" method="post" enctype="multipart/form-data" class="space-y-5" data-share-form>
      <div>
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Files</label>
        <input type="file" name="files" multiple accept="*/*" class="sr-only" data-file-input />
        <div class="rounded-lg border border-dashed border-border bg-cream p-5" data-dropzone>
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p class="text-sm text-ink-light">Select files and they upload immediately in the background.</p>
              <p class="text-xs text-ink-muted mt-1">You can keep filling in form details while upload progresses.</p>
            </div>
            <button type="button" class="px-4 py-2 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors" data-pick-files>Select files</button>
          </div>
          <p class="text-xs text-ink-muted mt-3" data-upload-status>{(stagedUploads.Count > 0 ? $"{stagedUploads.Count} file(s) uploaded and ready." : "No files uploaded yet.")}</p>
          <div class="mt-4 hidden" data-upload-hidden>{string.Join("", stagedUploads.Select(upload => $"""<input type="hidden" name="uploadedFileIds" value="{Html(upload.UploadId)}" data-uploaded-file-id />"""))}</div>
          <ul class="mt-3 grid grid-cols-2 lg:grid-cols-4 gap-2" data-upload-list>
            {string.Join("", stagedUploads.Select(upload => $"""
<li class="relative rounded-lg border border-sage/35 bg-sage-wash px-2.5 py-1.5 min-w-0" data-upload-id="{Html(upload.UploadId)}">
  <button type="button" class="absolute right-1 top-1 text-ink-muted hover:text-danger leading-none text-xs" title="Remove file" data-upload-remove aria-label="Remove file">x</button>
  <p class="text-xs text-ink-light truncate">{Html(upload.OriginalFileName)}</p>
  <p class="text-[11px] text-sage mt-0.5">Uploaded</p>
</li>
"""))}
          </ul>
        </div>
      </div>
      <div>
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Message (optional)</label>
        <textarea name="message" rows="3" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all resize-y"></textarea>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Zip filename</label>
          <input name="zipFileName" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" placeholder="Auto-generated if blank" />
        </div>
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Download password (optional)</label>
          <input type="password" name="downloadPassword" minlength="8" maxlength="256" autocomplete="new-password" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" placeholder="At least 8 characters" />
          <p class="text-[11px] text-ink-muted mt-1">When set, the ZIP is encrypted at rest and recipients must enter this password to download.</p>
        </div>
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Download notifications</label>
          <select name="notifyMode" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all appearance-none">
            <option value="account_default" selected>Account default ({Html(accountDefaultNotifyModeLabel)})</option>
            <option value="none">None</option>
            <option value="once">First download only</option>
            <option value="every_time">Every download</option>
          </select>
        </div>
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Expiry mode</label>
          <select name="expiryMode" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all appearance-none">
            <option value="account_default" selected>Account default ({Html(accountDefaultExpiryModeLabel)})</option>
            <option value="1_hour">1 hour</option>
            <option value="24_hours">24 hours</option>
            <option value="7_days">7 days</option>
            <option value="30_days">30 days</option>
            <option value="1_year">1 year</option>
            <option value="date">Date</option>
            <option value="indefinite">Indefinite</option>
          </select>
          <input type="hidden" value="{Html(accountDefaultExpiryMode)}" data-account-default-expiry-mode />
        </div>
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Expires at (local time)</label>
          <input type="datetime-local" name="expiresAtUtc" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
        </div>
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Download page design</label>
          <select name="templateMode" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all appearance-none" data-template-mode>
            <option value="account_default" {(templateModeForDraft == "account_default" ? "selected" : string.Empty)}>Account default</option>
            <option value="per_upload" {(templateModeForDraft == "per_upload" ? "selected" : string.Empty)}>Custom for this share</option>
          </select>
        </div>
        <div class="{(templateModeForDraft == "per_upload" ? string.Empty : "hidden")}" data-template-custom-actions>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Custom design</label>
          <a href="/share/landing-page-designer?draftShareId={Html(draftShareId)}" class="inline-block px-4 py-2 bg-ink text-white text-sm font-medium rounded-lg hover:bg-ink/90 transition-colors" data-template-designer-link>Change design</a>
        </div>
      </div>

      <input type="hidden" name="draftShareId" value="{Html(draftShareId)}" data-draft-share-id />
      <input type="hidden" name="template.title" value="{Html(draftTemplate.Title)}" data-template-title />
      <input type="hidden" name="template.h1" value="{Html(draftTemplate.H1)}" data-template-h1 />
      <input type="hidden" name="template.description" value="{Html(draftTemplate.Description)}" data-template-description />
      <input type="hidden" name="template.backgroundUploadId" value="{Html(draftTemplate.BackgroundUploadId)}" data-template-background-upload-id />
      <input type="hidden" name="template.backgroundColorHex" value="{Html(draftTemplate.BackgroundColorHex)}" data-template-background-color-hex />

      <div class="flex justify-end">
        <button type="submit" class="px-6 py-2.5 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors disabled:opacity-60 disabled:cursor-not-allowed" data-submit>Create share link</button>
      </div>
    </form>

    <dialog class="rounded-xl border border-border bg-white p-0 w-full max-w-sm backdrop:bg-black/30 m-auto" style="margin: auto;" data-upload-remove-dialog>
      <form method="dialog" class="p-5">
        <h3 class="font-display text-2xl tracking-tight">Remove file?</h3>
        <p class="text-sm text-ink-muted mt-2">This only removes the staged file from this draft share.</p>
        <p class="text-sm text-ink-light mt-2" data-upload-remove-file-name></p>
        <div class="mt-5 flex justify-end gap-2">
          <button type="button" class="px-4 py-2 text-sm border border-border rounded-lg bg-cream hover:bg-cream-dark/70" data-upload-remove-cancel>Cancel</button>
          <button type="button" class="px-4 py-2 text-sm bg-danger text-white rounded-lg hover:bg-danger/90" data-upload-remove-confirm>Remove</button>
        </div>
      </form>
    </dialog>
  </div>
</section>

{RenderShareUploaderScript()}
{RenderShareTemplateScript()}
""";

static string RenderAccountSettingsBody(string accountDefaultNotifyMode, string accountDefaultExpiryMode) => $"""
<section class="mb-8">
  <h2 class="font-display text-3xl tracking-tight">Account settings</h2>
  <p class="text-ink-muted text-sm mt-1">Manage share defaults and account-wide download page settings.</p>
</section>
<section id="share-defaults" class="mb-8 scroll-mt-24">
  <div class="bg-white rounded-2xl border border-border p-6">
    <h3 class="font-display text-xl mb-4">Share defaults</h3>
    <form action="/api/account/settings" method="post" class="space-y-4">
      <div class="max-w-sm">
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Default download notifications</label>
        <select name="defaultNotifyMode" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all appearance-none">
          <option value="once" {(accountDefaultNotifyMode == "once" ? "selected" : string.Empty)}>First download only</option>
          <option value="every_time" {(accountDefaultNotifyMode == "every_time" ? "selected" : string.Empty)}>Every download</option>
          <option value="none" {(accountDefaultNotifyMode == "none" ? "selected" : string.Empty)}>None</option>
        </select>
      </div>
      <div class="max-w-sm">
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Default expiry mode</label>
        <select name="defaultExpiryMode" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all appearance-none">
          <option value="1_hour" {(accountDefaultExpiryMode == "1_hour" ? "selected" : string.Empty)}>1 hour</option>
          <option value="24_hours" {(accountDefaultExpiryMode == "24_hours" ? "selected" : string.Empty)}>24 hours</option>
          <option value="7_days" {(accountDefaultExpiryMode == "7_days" ? "selected" : string.Empty)}>7 days</option>
          <option value="30_days" {(accountDefaultExpiryMode == "30_days" ? "selected" : string.Empty)}>30 days</option>
          <option value="1_year" {(accountDefaultExpiryMode == "1_year" ? "selected" : string.Empty)}>1 year</option>
          <option value="indefinite" {(accountDefaultExpiryMode == "indefinite" ? "selected" : string.Empty)}>Indefinite</option>
        </select>
      </div>
      <div class="flex justify-end">
        <button type="submit" class="px-6 py-2.5 bg-ink text-white text-sm font-medium rounded-lg hover:bg-ink/80 transition-colors">Save share defaults</button>
      </div>
    </form>
  </div>
</section>
<section id="landing-page-settings" class="scroll-mt-24">
  <div class="bg-white rounded-2xl border border-border p-6">
    <h3 class="font-display text-xl mb-2">Download page settings</h3>
    <p class="text-sm text-ink-light">Manage the account-wide download page template and background image.</p>
    <a href="/account/landing-page-designer" class="inline-block mt-4 px-4 py-2 bg-ink text-white text-sm font-medium rounded-lg hover:bg-ink/90 transition-colors">Open download page designer</a>
  </div>
</section>
""";

static string RenderAccountLandingPageDesignerBody(ShareTemplateData template)
{
    return $"""
<section class="mb-8">
  <h2 class="font-display text-3xl tracking-tight">Download page settings</h2>
  <p class="text-ink-muted text-sm mt-1">Set your account-wide default download page template.</p>
</section>
<section class="space-y-6">
  <div class="bg-white rounded-2xl border border-border p-6">
    <form method="post" action="/api/account/template" enctype="multipart/form-data" class="space-y-4" id="account-template-form">
      <div>
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Title</label>
        <input name="h1" value="{Html(template.H1)}" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra" data-preview-h1 />
      </div>
      <div>
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Subtitle</label>
        <input name="title" value="{Html(template.Title)}" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra" data-preview-title />
      </div>
      <div>
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Description</label>
        <textarea name="description" rows="3" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra" data-preview-description>{Html(template.Description)}</textarea>
      </div>
      <div>
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Background image</label>
        <input type="file" name="backgroundImageFile" accept=".jpg,.jpeg,.png,.svg,.webp" class="sr-only" data-preview-background-file />
        <div class="rounded-lg border border-dashed border-border bg-cream p-4" data-preview-upload-dropzone>
          <div class="flex items-center justify-between gap-3">
            <p class="text-xs text-ink-muted">.jpg, .jpeg, .png, .svg, .webp</p>
            <button type="button" class="px-3 py-1.5 bg-ink text-white text-xs font-medium rounded-md hover:bg-ink/90 transition-colors" data-preview-upload-pick>Select image</button>
          </div>
          <div class="mt-2 text-xs text-ink-muted" data-preview-upload-status>No file selected.</div>
        </div>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Background color</label>
          <select name="backgroundColorMode" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra" data-preview-background-color-mode>
            <option value="default" {(string.IsNullOrWhiteSpace(template.BackgroundColorHex) ? "selected" : string.Empty)}>Default</option>
            <option value="custom" {(!string.IsNullOrWhiteSpace(template.BackgroundColorHex) ? "selected" : string.Empty)}>Custom</option>
          </select>
        </div>
        <div data-preview-background-color-picker-wrap>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Pick color</label>
          <input type="color" name="backgroundColorHex" value="{Html(string.IsNullOrWhiteSpace(template.BackgroundColorHex) ? "#faf7f2" : template.BackgroundColorHex)}" class="h-10 w-full px-1 py-1 border border-border rounded-lg bg-cream" data-preview-background-color />
        </div>
      </div>
      <div class="flex items-center justify-between">
        <a href="/" class="text-sm text-ink-muted hover:text-ink">Back</a>
        <button type="submit" class="px-6 py-2.5 bg-ink text-white text-sm font-medium rounded-lg hover:bg-ink/90">Save template</button>
      </div>
    </form>
  </div>
  <div class="bg-white rounded-2xl border border-border p-6">
    <p class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-2">Preview</p>
    <div class="rounded-2xl border border-border p-4 bg-cover bg-center aspect-[4/3]" id="template-preview-card">
      <div class="h-full w-full flex items-center justify-center">
        <div class="bg-white/90 rounded-xl p-5 w-full max-w-xl shadow-sm">
          <h3 class="font-display text-3xl leading-tight" id="template-preview-h1">{Html(template.H1)}</h3>
          <p class="text-sm text-ink-light mt-2" id="template-preview-description">{Html(template.Description)}</p>
          <p class="text-xs text-ink-muted mt-1" id="template-preview-title">{Html(template.Title)}</p>

          <div class="mt-5 rounded-xl border border-border bg-cream px-4 py-3">
            <div class="flex items-center gap-3">
              <svg class="w-5 h-5 text-terra shrink-0" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"/></svg>
              <div>
                <p class="text-sm font-medium">example-share.zip</p>
                <p class="text-xs text-ink-muted">3 files &middot; 12.4 MB</p>
              </div>
            </div>
          </div>

          <p class="text-sm text-ink-light mt-4 p-3 bg-cream-dark rounded-lg"><span class="font-medium text-ink">Message:</span> Thanks for reviewing this share.</p>

          <div class="mt-5">
            <button type="button" class="w-full px-4 py-2.5 bg-terra text-white text-sm font-medium rounded-lg">Download</button>
          </div>
          <p class="text-[11px] text-ink-muted mt-4 text-center">Shared via Agora</p>
        </div>
      </div>
    </div>
  </div>
</section>
{RenderTemplateDesignerPreviewScript("account-template-form")}
""";
}

static string RenderShareLandingPageDesignerBody(string draftShareId, ShareManager.DraftTemplateState template) => $"""
<section class="mb-8">
  <h2 class="font-display text-3xl tracking-tight">Share download page designer</h2>
  <p class="text-ink-muted text-sm mt-1">Configure this share's download page. Save and return to the upload form.</p>
</section>
<section class="space-y-6">
  <div class="bg-white rounded-2xl border border-border p-6">
    <form id="share-template-form" class="space-y-4" method="post" action="/api/share-drafts/{Html(draftShareId)}/template">
      <div>
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Title</label>
        <input name="h1" data-template-h1 value="{Html(template.H1)}" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra" />
      </div>
      <div>
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Subtitle</label>
        <input name="title" data-template-title value="{Html(template.Title)}" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra" />
      </div>
      <div>
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Description</label>
        <textarea rows="3" name="description" data-template-description class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra">{Html(template.Description)}</textarea>
      </div>
      <div>
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Background image</label>
        <input type="hidden" name="backgroundUploadId" value="{Html(template.BackgroundUploadId)}" data-template-background-upload-id />
        <input type="hidden" name="backgroundColorHex" value="{Html(template.BackgroundColorHex)}" data-template-background-color-hex />
        <input type="hidden" value="{Html(draftShareId)}" data-draft-share-id />
        <input type="file" accept=".jpg,.jpeg,.png,.svg,.webp" data-template-background-file class="sr-only" />
        <div class="rounded-lg border border-dashed border-border bg-cream p-4" data-template-upload-dropzone>
          <div class="flex items-center justify-between gap-3">
            <p class="text-xs text-ink-muted">.jpg, .jpeg, .png, .svg, .webp</p>
            <button type="button" class="px-3 py-1.5 bg-ink text-white text-xs font-medium rounded-md hover:bg-ink/90 transition-colors" data-template-upload-pick>Select image</button>
          </div>
          <div class="mt-2 text-xs text-ink-muted" data-template-upload-status>No uploaded background image.</div>
        </div>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Background color</label>
          <select class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra" data-template-background-color-mode>
            <option value="default" {(string.IsNullOrWhiteSpace(template.BackgroundColorHex) ? "selected" : string.Empty)}>Default</option>
            <option value="custom" {(!string.IsNullOrWhiteSpace(template.BackgroundColorHex) ? "selected" : string.Empty)}>Custom</option>
          </select>
        </div>
        <div data-template-background-color-picker-wrap>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Pick color</label>
          <input type="color" value="{Html(string.IsNullOrWhiteSpace(template.BackgroundColorHex) ? "#faf7f2" : template.BackgroundColorHex)}" class="h-10 w-full px-1 py-1 border border-border rounded-lg bg-cream" data-template-background-color />
        </div>
      </div>
      <div class="flex items-center justify-between">
        <a href="/shares/new?draftShareId={Html(draftShareId)}" class="text-sm text-ink-muted hover:text-ink">Cancel</a>
        <button type="submit" class="px-6 py-2.5 bg-ink text-white text-sm font-medium rounded-lg hover:bg-ink/90">Save and return</button>
      </div>
    </form>
  </div>
  <div class="bg-white rounded-2xl border border-border p-6">
    <p class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-2">Preview</p>
    <div class="rounded-2xl border border-border p-4 bg-cover bg-center aspect-[4/3]" data-preview-card>
      <div class="h-full w-full flex items-center justify-center">
        <div class="bg-white/90 rounded-xl p-5 w-full max-w-xl shadow-sm">
          <h3 class="font-display text-3xl leading-tight" data-preview-h1>{Html(string.IsNullOrWhiteSpace(template.H1) ? "A file was shared with you" : template.H1)}</h3>
          <p class="text-sm text-ink-light mt-2" data-preview-description>{Html(string.IsNullOrWhiteSpace(template.Description) ? "Use the button below to download your file." : template.Description)}</p>
          <p class="text-xs text-ink-muted mt-1" data-preview-title>{Html(string.IsNullOrWhiteSpace(template.Title) ? "Shared file" : template.Title)}</p>

          <div class="mt-5 rounded-xl border border-border bg-cream px-4 py-3">
            <div class="flex items-center gap-3">
              <svg class="w-5 h-5 text-terra shrink-0" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"/></svg>
              <div>
                <p class="text-sm font-medium">example-share.zip</p>
                <p class="text-xs text-ink-muted">3 files &middot; 12.4 MB</p>
              </div>
            </div>
          </div>

          <p class="text-sm text-ink-light mt-4 p-3 bg-cream-dark rounded-lg"><span class="font-medium text-ink">Message:</span> Thanks for reviewing this share.</p>

          <div class="mt-5">
            <button type="button" class="w-full px-4 py-2.5 bg-terra text-white text-sm font-medium rounded-lg">Download</button>
          </div>
          <p class="text-[11px] text-ink-muted mt-4 text-center">Shared via Agora</p>
        </div>
      </div>
    </div>
  </div>
</section>
{RenderShareTemplateDesignerScript()}
""";

static string RenderTemplateDesignerPreviewScript(string formId) => $$"""
<script>
(() => {
  const form = document.getElementById('{{formId}}');
  if (!form) return;

  const titleInput = form.querySelector('[data-preview-title]');
  const h1Input = form.querySelector('[data-preview-h1]');
  const descriptionInput = form.querySelector('[data-preview-description]');
  const backgroundFileInput = form.querySelector('[data-preview-background-file]');
  const backgroundColorModeInput = form.querySelector('[data-preview-background-color-mode]');
  const backgroundColorInput = form.querySelector('[data-preview-background-color]');
  const backgroundColorWrap = form.querySelector('[data-preview-background-color-picker-wrap]');
  const uploadPick = form.querySelector('[data-preview-upload-pick]');
  const uploadDropzone = form.querySelector('[data-preview-upload-dropzone]');
  const uploadStatus = form.querySelector('[data-preview-upload-status]');

  const titleTarget = document.getElementById('template-preview-title');
  const h1Target = document.getElementById('template-preview-h1');
  const descriptionTarget = document.getElementById('template-preview-description');
  const card = document.getElementById('template-preview-card');
  const allowedExtensions = new Set(['.jpg', '.jpeg', '.png', '.svg', '.webp']);
  let uploadedPreviewUrl = '';

  const updatePreview = () => {
    titleTarget.textContent = titleInput.value || 'Shared file';
    h1Target.textContent = h1Input.value || 'A file was shared with you';
    descriptionTarget.textContent = descriptionInput.value || 'Use the button below to download your file.';
    const customBackgroundColor = backgroundColorModeInput && backgroundColorModeInput.value === 'custom' && backgroundColorInput
      ? backgroundColorInput.value
      : '';
    card.style.backgroundColor = customBackgroundColor || '';
    card.style.backgroundImage = uploadedPreviewUrl ? ('url(' + uploadedPreviewUrl + ')') : '';
  };

  [titleInput, h1Input, descriptionInput].forEach((el) => el.addEventListener('input', updatePreview));
  if (backgroundColorModeInput && backgroundColorInput) {
    const refreshColorMode = () => {
      const isCustom = backgroundColorModeInput.value === 'custom';
      if (backgroundColorWrap) {
        backgroundColorWrap.classList.toggle('hidden', !isCustom);
      }
      backgroundColorInput.name = isCustom ? 'backgroundColorHex' : '';
      if (!isCustom) {
        backgroundColorInput.value = '#faf7f2';
      }
      updatePreview();
    };
    backgroundColorModeInput.addEventListener('change', refreshColorMode);
    backgroundColorInput.addEventListener('input', updatePreview);
    refreshColorMode();
  }

  const setStatus = (text, isError) => {
    if (!uploadStatus) return;
    uploadStatus.textContent = text;
    uploadStatus.classList.remove('text-ink-muted', 'text-danger', 'text-sage');
    uploadStatus.classList.add(isError ? 'text-danger' : 'text-ink-muted');
  };

  const setSelectedFile = (file) => {
    if (!backgroundFileInput || !file) return;
    const dt = new DataTransfer();
    dt.items.add(file);
    backgroundFileInput.files = dt.files;
  };

  const handleSelectedFiles = (files) => {
    const list = Array.from(files || []);
    if (list.length === 0) return;
    if (list.length > 1) {
      setStatus('Only one image can be selected.', true);
      return;
    }

    const file = list[0];
    const ext = file.name.toLowerCase().includes('.')
      ? file.name.toLowerCase().slice(file.name.lastIndexOf('.'))
      : '';
    if (!allowedExtensions.has(ext)) {
      setStatus('Only JPG, PNG, SVG, or WEBP files are allowed.', true);
      return;
    }

    setSelectedFile(file);
    if (uploadedPreviewUrl) {
      URL.revokeObjectURL(uploadedPreviewUrl);
    }
    uploadedPreviewUrl = URL.createObjectURL(file);
    setStatus('Selected: ' + file.name, false);
    updatePreview();
  };

  if (uploadPick && backgroundFileInput) {
    uploadPick.addEventListener('click', () => backgroundFileInput.click());
  }

  if (backgroundFileInput) {
    backgroundFileInput.addEventListener('change', () => {
      handleSelectedFiles(backgroundFileInput.files);
    });
  }

  if (uploadDropzone) {
    uploadDropzone.addEventListener('dragover', (event) => {
      event.preventDefault();
      uploadDropzone.classList.add('ring-2', 'ring-terra/40');
    });
    uploadDropzone.addEventListener('dragleave', () => {
      uploadDropzone.classList.remove('ring-2', 'ring-terra/40');
    });
    uploadDropzone.addEventListener('drop', (event) => {
      event.preventDefault();
      uploadDropzone.classList.remove('ring-2', 'ring-terra/40');
      handleSelectedFiles(event.dataTransfer ? event.dataTransfer.files : []);
    });
  }

  updatePreview();
})();
</script>
""";

static string RenderShareTemplateDesignerScript() => """
<script>
(() => {
  const form = document.getElementById('share-template-form');
  if (!form) return;

  const titleInput = form.querySelector('[data-template-title]');
  const h1Input = form.querySelector('[data-template-h1]');
  const descriptionInput = form.querySelector('[data-template-description]');
  const backgroundFileInput = form.querySelector('[data-template-background-file]');
  const backgroundUploadIdInput = form.querySelector('[data-template-background-upload-id]');
  const backgroundColorHexInput = form.querySelector('[data-template-background-color-hex]');
  const backgroundColorModeInput = form.querySelector('[data-template-background-color-mode]');
  const backgroundColorInput = form.querySelector('[data-template-background-color]');
  const backgroundColorWrap = form.querySelector('[data-template-background-color-picker-wrap]');
  const draftShareIdInput = form.querySelector('[data-draft-share-id]');
  const uploadDropzone = form.querySelector('[data-template-upload-dropzone]');
  const uploadPick = form.querySelector('[data-template-upload-pick]');
  const uploadStatus = form.querySelector('[data-template-upload-status]');
  const previewTitle = document.querySelector('[data-preview-title]');
  const previewH1 = document.querySelector('[data-preview-h1]');
  const previewDescription = document.querySelector('[data-preview-description]');
  const previewCard = document.querySelector('[data-preview-card]');
  const allowedExtensions = new Set(['.jpg', '.jpeg', '.png', '.svg', '.webp']);

  let backgroundUploadId = '';
  let uploadedPreviewUrl = '';

  const updatePreview = () => {
    previewTitle.textContent = titleInput.value || 'Shared file';
    previewH1.textContent = h1Input.value || 'A file was shared with you';
    previewDescription.textContent = descriptionInput.value || 'Use the button below to download your file.';
    const customBackgroundColor = backgroundColorModeInput && backgroundColorModeInput.value === 'custom' && backgroundColorInput
      ? backgroundColorInput.value
      : '';
    previewCard.style.backgroundColor = customBackgroundColor || '';
    previewCard.style.backgroundImage = uploadedPreviewUrl ? ('url(' + uploadedPreviewUrl + ')') : '';
  };

  const setStatus = (text, isError) => {
    uploadStatus.textContent = text;
    uploadStatus.classList.remove('text-ink-muted', 'text-danger');
    uploadStatus.classList.add(isError ? 'text-danger' : 'text-ink-muted');
  };

  const stageBackground = (file) => {
    setStatus('Uploading background image...', false);
    const formData = new FormData();
    formData.append('file', file, file.name);
    if (draftShareIdInput && draftShareIdInput.value) {
      formData.append('draftShareId', draftShareIdInput.value);
    }
    fetch('/api/uploads/stage-template-background', { method: 'POST', body: formData })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error('Upload failed')))
      .then((json) => {
        backgroundUploadId = json.uploadId || '';
        if (backgroundUploadIdInput) {
          backgroundUploadIdInput.value = backgroundUploadId;
        }
        if (uploadedPreviewUrl) {
          URL.revokeObjectURL(uploadedPreviewUrl);
        }
        uploadedPreviewUrl = URL.createObjectURL(file);
        setStatus(backgroundUploadId ? ('Uploaded: ' + (json.fileName || file.name)) : 'Upload failed.', !backgroundUploadId);
        updatePreview();
      })
      .catch(() => {
        backgroundUploadId = '';
        setStatus('Upload failed.', true);
      });
  };

  const setSelectedFile = (file) => {
    if (!backgroundFileInput || !file) return;
    const dt = new DataTransfer();
    dt.items.add(file);
    backgroundFileInput.files = dt.files;
  };

  const handleSelectedFiles = (files) => {
    const list = Array.from(files || []);
    if (list.length === 0) return;
    if (list.length > 1) {
      setStatus('Only one image can be selected.', true);
      return;
    }

    const file = list[0];
    const ext = file.name.toLowerCase().includes('.')
      ? file.name.toLowerCase().slice(file.name.lastIndexOf('.'))
      : '';
    if (!allowedExtensions.has(ext)) {
      setStatus('Only JPG, PNG, SVG, or WEBP files are allowed.', true);
      return;
    }

    setSelectedFile(file);
    stageBackground(file);
  };
  [titleInput, h1Input, descriptionInput].forEach((el) => el.addEventListener('input', updatePreview));
  if (backgroundColorModeInput && backgroundColorInput && backgroundColorHexInput) {
    const refreshColorMode = () => {
      const isCustom = backgroundColorModeInput.value === 'custom';
      if (backgroundColorWrap) {
        backgroundColorWrap.classList.toggle('hidden', !isCustom);
      }
      backgroundColorHexInput.value = isCustom ? backgroundColorInput.value : '';
      updatePreview();
    };
    backgroundColorModeInput.addEventListener('change', refreshColorMode);
    backgroundColorInput.addEventListener('input', () => {
      if (backgroundColorModeInput.value === 'custom') {
        backgroundColorHexInput.value = backgroundColorInput.value;
      }
      updatePreview();
    });
    refreshColorMode();
  }
  if (uploadPick && backgroundFileInput) {
    uploadPick.addEventListener('click', () => backgroundFileInput.click());
  }
  backgroundFileInput.addEventListener('change', () => {
    handleSelectedFiles(backgroundFileInput.files);
  });
  if (uploadDropzone) {
    uploadDropzone.addEventListener('dragover', (event) => {
      event.preventDefault();
      uploadDropzone.classList.add('ring-2', 'ring-terra/40');
    });
    uploadDropzone.addEventListener('dragleave', () => {
      uploadDropzone.classList.remove('ring-2', 'ring-terra/40');
    });
    uploadDropzone.addEventListener('drop', (event) => {
      event.preventDefault();
      uploadDropzone.classList.remove('ring-2', 'ring-terra/40');
      handleSelectedFiles(event.dataTransfer ? event.dataTransfer.files : []);
    });
  }

  if (backgroundUploadIdInput && backgroundUploadIdInput.value) {
    setStatus('Uploaded background image selected.', false);
  }
  updatePreview();
})();
</script>
""";

static string RenderShareUploaderScript() => """
<script>
(() => {
  const form = document.querySelector('[data-share-form]');
  if (!form) return;

  const fileInput = form.querySelector('[data-file-input]');
  const pickButton = form.querySelector('[data-pick-files]');
  const list = form.querySelector('[data-upload-list]');
  const hidden = form.querySelector('[data-upload-hidden]');
  const status = form.querySelector('[data-upload-status]');
  const submit = form.querySelector('[data-submit]');
  const dropzone = form.querySelector('[data-dropzone]');
  const expiryModeInput = form.querySelector('[name="expiryMode"]');
  const expiresAtInput = form.querySelector('[name="expiresAtUtc"]');
  const accountDefaultExpiryInput = form.querySelector('[data-account-default-expiry-mode]');
  const draftShareIdInput = form.querySelector('[data-draft-share-id]');
  const removeDialog = form.querySelector('[data-upload-remove-dialog]');
  const removeName = form.querySelector('[data-upload-remove-file-name]');
  const removeCancel = form.querySelector('[data-upload-remove-cancel]');
  const removeConfirm = form.querySelector('[data-upload-remove-confirm]');

  const uploadedIds = new Set();
  hidden.querySelectorAll('input[name="uploadedFileIds"]').forEach((input) => {
    if (input && input.value) {
      uploadedIds.add(input.value);
    }
  });
  let activeUploads = 0;
  let pendingRemoval = null;

  const formatBytes = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
  };

  const formatLocalDateTimeForInput = (date) => {
    const pad = (value) => String(value).padStart(2, '0');
    return date.getFullYear() + '-' +
      pad(date.getMonth() + 1) + '-' +
      pad(date.getDate()) + 'T' +
      pad(date.getHours()) + ':' +
      pad(date.getMinutes());
  };

  const getPresetExpiryDate = (mode) => {
    const now = new Date();
    const date = new Date(now.getTime());
    if (mode === '1_hour') date.setHours(date.getHours() + 1);
    else if (mode === '24_hours') date.setHours(date.getHours() + 24);
    else if (mode === '7_days') date.setDate(date.getDate() + 7);
    else if (mode === '30_days') date.setDate(date.getDate() + 30);
    else if (mode === '1_year') date.setFullYear(date.getFullYear() + 1);
    else return null;
    return date;
  };

  const resolveEffectiveExpiryMode = () => {
    if (!expiryModeInput) return 'date';
    if (expiryModeInput.value !== 'account_default') return expiryModeInput.value;
    return accountDefaultExpiryInput && accountDefaultExpiryInput.value
      ? accountDefaultExpiryInput.value
      : '7_days';
  };

  const updateExpiryUi = () => {
    if (!expiryModeInput || !expiresAtInput) return;
    const mode = resolveEffectiveExpiryMode();

    if (mode === 'date') {
      expiresAtInput.disabled = false;
      return;
    }

    expiresAtInput.disabled = true;
    if (mode === 'indefinite') {
      expiresAtInput.value = '';
      return;
    }

    const presetDate = getPresetExpiryDate(mode);
    if (presetDate) {
      expiresAtInput.value = formatLocalDateTimeForInput(presetDate);
    }
  };

  const getDisabledReason = () => {
    if (activeUploads > 0) {
      return 'Please wait for uploads to finish.';
    }

    if (uploadedIds.size === 0) {
      return 'Upload at least one file first.';
    }

    if (expiryModeInput && resolveEffectiveExpiryMode() === 'date') {
      if (!expiresAtInput || !expiresAtInput.value) {
        return 'Pick an expiry date and time.';
      }

      const expiresAt = new Date(expiresAtInput.value).getTime();
      if (Number.isNaN(expiresAt) || expiresAt <= Date.now()) {
        return 'Expiry date must be in the future.';
      }
    }

    return '';
  };

  const refreshState = () => {
    const reason = getDisabledReason();
    submit.disabled = reason.length > 0;
    submit.title = reason;
    submit.setAttribute('aria-label', reason.length > 0 ? reason : 'Create share link');

    if (activeUploads > 0) {
      status.textContent = 'Uploading ' + activeUploads + ' file(s)...';
      return;
    }

    status.textContent = uploadedIds.size > 0
      ? uploadedIds.size + ' file(s) uploaded and ready.'
      : 'No files uploaded yet.';
  };

  const addHiddenField = (uploadId) => {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'uploadedFileIds';
    input.value = uploadId;
    input.setAttribute('data-uploaded-file-id', uploadId);
    hidden.appendChild(input);
  };

  const removeHiddenField = (uploadId) => {
    hidden.querySelectorAll('input[name="uploadedFileIds"]').forEach((input) => {
      if (input.value === uploadId) {
        input.remove();
      }
    });
  };

  const requestRemoveUpload = (uploadId, fileName, row) => {
    pendingRemoval = { uploadId, row };
    if (removeName) {
      removeName.textContent = fileName || '';
    }

    if (removeDialog && typeof removeDialog.showModal === 'function') {
      removeDialog.showModal();
      return;
    }

    if (window.confirm('Remove "' + (fileName || 'this file') + '" from this share?')) {
      confirmRemoveUpload();
    } else {
      pendingRemoval = null;
    }
  };

  const confirmRemoveUpload = () => {
    if (!pendingRemoval) {
      return;
    }

    const uploadId = pendingRemoval.uploadId;
    const row = pendingRemoval.row;
    pendingRemoval = null;

    const formData = new FormData();
    formData.append('uploadId', uploadId);
    if (draftShareIdInput && draftShareIdInput.value) {
      formData.append('draftShareId', draftShareIdInput.value);
    }

    fetch('/api/uploads/remove', { method: 'POST', body: formData })
      .then((response) => {
        if (!response.ok) {
          return Promise.reject(new Error('Unable to remove file.'));
        }
        uploadedIds.delete(uploadId);
        removeHiddenField(uploadId);
        if (row && row.parentElement) {
          row.remove();
        }
        refreshState();
      })
      .catch(() => {
        status.textContent = 'Unable to remove file right now.';
      });
  };

  const createRow = (file) => {
    const row = document.createElement('li');
    row.className = 'relative rounded-lg border border-border bg-cream px-2.5 py-2 min-w-0';

    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'absolute right-1 top-1 text-ink-muted hover:text-danger leading-none text-xs hidden';
    remove.title = 'Remove file';
    remove.setAttribute('aria-label', 'Remove file');
    remove.setAttribute('data-upload-remove', '');
    remove.textContent = 'x';

    const name = document.createElement('p');
    name.className = 'text-xs text-ink-light truncate';
    name.textContent = file.name;

    const size = document.createElement('p');
    size.className = 'text-[11px] text-ink-muted mt-0.5';
    size.textContent = formatBytes(file.size);

    const progressWrap = document.createElement('div');
    progressWrap.className = 'mt-1.5 h-1 bg-white rounded-full overflow-hidden';
    const bar = document.createElement('div');
    bar.className = 'h-full bg-terra transition-all';
    bar.style.width = '0%';
    progressWrap.appendChild(bar);

    const state = document.createElement('p');
    state.className = 'text-[11px] text-ink-muted mt-1';
    state.textContent = 'Queued...';

    row.appendChild(remove);
    row.appendChild(name);
    row.appendChild(size);
    row.appendChild(progressWrap);
    row.appendChild(state);
    list.appendChild(row);
    return { row, bar, state, progressWrap, size, remove, fileName: file.name };
  };

  const uploadFile = (file) => {
    const ui = createRow(file);
    activeUploads += 1;
    refreshState();

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/uploads/stage');
    xhr.responseType = 'json';

    xhr.upload.addEventListener('progress', (event) => {
      if (!event.lengthComputable) return;
      const percent = Math.min(100, Math.round((event.loaded / event.total) * 100));
      ui.bar.style.width = percent + '%';
      ui.state.textContent = 'Uploading... ' + percent + '%';
    });

    xhr.addEventListener('load', () => {
      activeUploads -= 1;
      if (xhr.status >= 200 && xhr.status < 300 && xhr.response && xhr.response.uploadId) {
        const uploadId = xhr.response.uploadId;
        ui.row.setAttribute('data-upload-id', uploadId);
        uploadedIds.add(xhr.response.uploadId);
        addHiddenField(xhr.response.uploadId);
        ui.row.className = 'relative rounded-lg border border-sage/35 bg-sage-wash px-2.5 py-1.5 min-w-0';
        ui.progressWrap.style.display = 'none';
        ui.size.style.display = 'none';
        ui.state.textContent = 'Uploaded';
        ui.state.className = 'text-[11px] text-sage mt-0.5';
        ui.remove.classList.remove('hidden');
        ui.remove.addEventListener('click', () => requestRemoveUpload(uploadId, ui.fileName, ui.row));
      } else {
        ui.row.className = 'relative rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0';
        ui.bar.className = 'h-full bg-danger';
        ui.state.textContent = 'Upload failed';
        ui.state.className = 'text-[11px] text-danger mt-1';
      }
      refreshState();
    });

    xhr.addEventListener('error', () => {
      activeUploads -= 1;
      ui.row.className = 'relative rounded-lg border border-danger/35 bg-danger-wash px-2.5 py-2 min-w-0';
      ui.bar.className = 'h-full bg-danger';
      ui.state.textContent = 'Upload failed';
      ui.state.className = 'text-[11px] text-danger mt-1';
      refreshState();
    });

    const data = new FormData();
    data.append('file', file, file.name);
    if (draftShareIdInput && draftShareIdInput.value) {
      data.append('draftShareId', draftShareIdInput.value);
    }
    xhr.send(data);
  };

  const queueFiles = (files) => {
    Array.from(files || []).forEach((file) => uploadFile(file));
    if (fileInput) fileInput.value = '';
  };

  if (pickButton && fileInput) {
    pickButton.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => queueFiles(fileInput.files));
  }

  if (dropzone) {
    dropzone.addEventListener('dragover', (event) => {
      event.preventDefault();
      dropzone.classList.add('ring-2', 'ring-terra/40');
    });
    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('ring-2', 'ring-terra/40');
    });
    dropzone.addEventListener('drop', (event) => {
      event.preventDefault();
      dropzone.classList.remove('ring-2', 'ring-terra/40');
      queueFiles(event.dataTransfer ? event.dataTransfer.files : []);
    });
  }

  list.querySelectorAll('[data-upload-remove]').forEach((button) => {
    button.addEventListener('click', () => {
      const row = button.closest('[data-upload-id]');
      if (!row) return;
      const uploadId = row.getAttribute('data-upload-id') || '';
      const fileNameNode = row.querySelector('p');
      const fileName = fileNameNode ? fileNameNode.textContent || '' : '';
      if (!uploadId) return;
      requestRemoveUpload(uploadId, fileName, row);
    });
  });

  if (removeCancel) {
    removeCancel.addEventListener('click', () => {
      pendingRemoval = null;
      if (removeDialog) {
        removeDialog.close();
      }
    });
  }

  if (removeConfirm) {
    removeConfirm.addEventListener('click', () => {
      if (removeDialog) {
        removeDialog.close();
      }
      confirmRemoveUpload();
    });
  }

  if (expiryModeInput) {
    expiryModeInput.addEventListener('change', () => {
      updateExpiryUi();
      refreshState();
    });
  }

  if (expiresAtInput) {
    expiresAtInput.addEventListener('input', refreshState);
    expiresAtInput.addEventListener('change', refreshState);
  }

  form.addEventListener('submit', (event) => {
    const reason = getDisabledReason();
    if (reason.length > 0) {
      event.preventDefault();
      status.textContent = reason;
    }
  });

  updateExpiryUi();
  refreshState();
})();
</script>
""";

static string RenderShareTemplateScript() => """
<script>
(() => {
  const form = document.querySelector('[data-share-form]');
  if (!form) return;

  const summary = form.querySelector('[data-template-summary]');
  const modeInput = form.querySelector('[data-template-mode]');
  const titleInput = form.querySelector('[data-template-title]');
  const h1Input = form.querySelector('[data-template-h1]');
  const customActions = form.querySelector('[data-template-custom-actions]');
  const designerLink = form.querySelector('[data-template-designer-link]');

  const refreshSummary = () => {
    if (modeInput.value !== 'per_upload') {
      if (summary) {
        summary.textContent = 'Using account default template.';
      }
      if (customActions) customActions.classList.add('hidden');
      return;
    }

    const heading = h1Input.value || titleInput.value || 'Untitled';
    if (summary) {
      summary.textContent = 'Custom design selected: ' + heading + '.';
    }
    if (customActions) customActions.classList.remove('hidden');
  };

  if (designerLink) {
    designerLink.addEventListener('click', (event) => {
      if (modeInput.value !== 'per_upload') {
        event.preventDefault();
      }
    });
  }

  modeInput.addEventListener('change', refreshSummary);
  refreshSummary();
})();
</script>
""";

static string RenderLocalDateTimeScript() => """
<script>
(() => {
  const nodes = document.querySelectorAll('[data-local-datetime]');
  if (!nodes.length) return;

  const formatter = new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short'
  });

  nodes.forEach((node) => {
    const value = node.getAttribute('data-local-datetime');
    if (!value) return;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return;
    node.textContent = formatter.format(date);
  });
})();
</script>
""";

static string RenderShareDeleteScript() => """
<script>
(() => {
  const dialog = document.querySelector('[data-share-delete-dialog]');
  if (!dialog) return;

  const nameNode = dialog.querySelector('[data-share-delete-name]');
  const cancelButton = dialog.querySelector('[data-share-delete-cancel]');
  const confirmButton = dialog.querySelector('[data-share-delete-confirm]');
  let pendingForm = null;

  document.querySelectorAll('[data-share-delete-trigger]').forEach((button) => {
    button.addEventListener('click', () => {
      const form = button.closest('[data-share-delete-form]');
      if (!form) return;
      pendingForm = form;
      if (nameNode) {
        nameNode.textContent = form.getAttribute('data-share-name') || '';
      }
      dialog.showModal();
    });
  });

  if (cancelButton) {
    cancelButton.addEventListener('click', () => dialog.close());
  }

  if (confirmButton) {
    confirmButton.addEventListener('click', () => {
      if (pendingForm) {
        pendingForm.submit();
      }
      dialog.close();
    });
  }
})();
</script>
""";

static string RenderQuickShareDropzoneScript() => """
<script>
(() => {
  const dropzone = document.querySelector('[data-quick-share-dropzone]');
  const fileInput = document.querySelector('[data-quick-share-input]');
  const pickButton = document.querySelector('[data-quick-share-pick]');
  const status = document.querySelector('[data-quick-share-status]');
  const draftIdInput = document.querySelector('[data-quick-share-draft-id]');
  if (!dropzone || !fileInput || !pickButton || !status || !draftIdInput || !draftIdInput.value) return;

  const draftShareId = draftIdInput.value;

  const setStatus = (text, isError) => {
    status.textContent = text;
    status.classList.remove('text-ink-muted', 'text-danger');
    status.classList.add(isError ? 'text-danger' : 'text-ink-muted');
  };

  const uploadSingleFile = async (file) => {
    const formData = new FormData();
    formData.append('draftShareId', draftShareId);
    formData.append('file', file, file.name);

    const response = await fetch('/api/uploads/stage', {
      method: 'POST',
      body: formData
    });
    if (!response.ok) {
      let error = 'Upload failed.';
      try {
        const json = await response.json();
        if (json && json.error) {
          error = json.error;
        }
      } catch {
        // ignore non-json responses
      }
      throw new Error(error);
    }
  };

  const queueAndUpload = async (files) => {
    const list = Array.from(files || []);
    if (list.length === 0) return;

    setStatus('Uploading ' + list.length + ' file(s)...', false);
    try {
      for (const file of list) {
        await uploadSingleFile(file);
      }
      setStatus('Upload complete. Redirecting to share setup...', false);
      window.location.href = '/shares/new?draftShareId=' + encodeURIComponent(draftShareId);
    } catch (error) {
      setStatus((error && error.message) ? error.message : 'Upload failed.', true);
    }
  };

  pickButton.addEventListener('click', (event) => {
    event.stopPropagation();
    fileInput.click();
  });

  dropzone.addEventListener('click', () => fileInput.click());
  dropzone.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      fileInput.click();
    }
  });

  fileInput.addEventListener('change', () => {
    queueAndUpload(fileInput.files);
    fileInput.value = '';
  });

  dropzone.addEventListener('dragover', (event) => {
    event.preventDefault();
    dropzone.classList.add('ring-2', 'ring-terra/40');
  });
  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('ring-2', 'ring-terra/40');
  });
  dropzone.addEventListener('drop', (event) => {
    event.preventDefault();
    dropzone.classList.remove('ring-2', 'ring-terra/40');
    queueAndUpload(event.dataTransfer ? event.dataTransfer.files : []);
  });
})();
</script>
""";

static string RenderCsrfClientScript() => """
<script>
(() => {
  const cookieName = 'agora.csrf.request';
  const formFieldName = '__RequestVerificationToken';
  const headerName = 'X-CSRF-TOKEN';

  const getCookie = (name) => {
    const prefix = name + '=';
    const parts = document.cookie ? document.cookie.split(';') : [];
    for (const part of parts) {
      const value = part.trim();
      if (value.startsWith(prefix)) {
        return decodeURIComponent(value.slice(prefix.length));
      }
    }
    return '';
  };

  const csrfToken = getCookie(cookieName);
  if (!csrfToken) return;

  const isUnsafeMethod = (method) => {
    const upper = (method || 'GET').toUpperCase();
    return upper !== 'GET' && upper !== 'HEAD' && upper !== 'OPTIONS' && upper !== 'TRACE';
  };

  const isSameOriginUrl = (input) => {
    try {
      const url = new URL(input || window.location.href, window.location.href);
      return url.origin === window.location.origin;
    } catch {
      return false;
    }
  };

  document.querySelectorAll('form').forEach((form) => {
    const method = form.getAttribute('method') || 'GET';
    if (!isUnsafeMethod(method)) return;
    if (form.querySelector('input[name="' + formFieldName + '"]')) return;
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = formFieldName;
    input.value = csrfToken;
    form.appendChild(input);
  });

  const originalFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    const method = (init && init.method) || 'GET';
    const url = typeof input === 'string' ? input : (input && input.url) || window.location.href;
    if (!isUnsafeMethod(method) || !isSameOriginUrl(url)) {
      return originalFetch(input, init);
    }

    const requestInit = init ? { ...init } : {};
    const headers = new Headers(requestInit.headers || (typeof input !== 'string' ? input.headers : undefined));
    if (!headers.has(headerName)) {
      headers.set(headerName, csrfToken);
    }
    requestInit.headers = headers;
    return originalFetch(input, requestInit);
  };

  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(method, url) {
    this._csrfMethod = method || 'GET';
    this._csrfUrl = url || window.location.href;
    return originalOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function(body) {
    if (isUnsafeMethod(this._csrfMethod) && isSameOriginUrl(this._csrfUrl)) {
      this.setRequestHeader(headerName, csrfToken);
    }
    return originalSend.call(this, body);
  };
})();
</script>
""";

static string RenderLayout(string title, string? email, string body, string? message = null, bool isAdmin = false)
{
    var safeTitle = Html(title);

    var messageHtml = string.IsNullOrWhiteSpace(message)
        ? string.Empty
        : $"""<div class="mb-6 px-4 py-3 bg-terra-wash border border-terra-light/30 rounded-xl text-sm text-ink-light">{Html(message)}</div>""";

    var authBlock = string.IsNullOrWhiteSpace(email)
        ? string.Empty
        : $"""
<nav class="flex items-center gap-4">
  <details class="relative">
    <summary class="list-none cursor-pointer">
      <span class="inline-flex items-center gap-2 rounded-lg border border-border bg-white px-3 py-1.5 text-sm text-ink-light hover:border-terra/40">
        <span class="w-6 h-6 rounded-full bg-cream-dark text-ink-muted flex items-center justify-center" aria-hidden="true">
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6.75a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.5 19.125a7.5 7.5 0 0115 0"/></svg>
        </span>
        <span class="text-[11px] text-ink-muted leading-tight">{Html(email)}</span>
      </span>
    </summary>
    <div class="absolute right-0 mt-2 w-56 rounded-xl border border-border bg-white p-2 shadow-lg z-20">
      <a href="/account/settings" class="block rounded-lg px-3 py-2 text-sm text-ink-light hover:bg-cream-dark/60">Account settings</a>
      <a href="/account/landing-page-designer" class="block rounded-lg px-3 py-2 text-sm text-ink-light hover:bg-cream-dark/60">Download page settings</a>
      <a href="/account/share-defaults" class="block rounded-lg px-3 py-2 text-sm text-ink-light hover:bg-cream-dark/60">Share defaults</a>
      {(isAdmin ? """<div class="my-1 border-t border-border"></div><p class="px-3 py-1 text-[11px] font-medium uppercase tracking-wider text-ink-muted">Admin</p><a href="/admin" class="block rounded-lg px-3 py-2 text-sm text-ink-light hover:bg-cream-dark/60">Manage users</a><a href="/hangfire" class="block rounded-lg px-3 py-2 text-sm text-ink-light hover:bg-cream-dark/60">Manage jobs</a>""" : string.Empty)}
      <div class="my-1 border-t border-border"></div>
      <form method="post" action="/logout">
        <button type="submit" class="w-full text-left rounded-lg px-3 py-2 text-sm text-ink-muted hover:bg-cream-dark/60">Sign out</button>
      </form>
    </div>
  </details>
</nav>
""";

    return $"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{safeTitle}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600&family=Instrument+Serif:ital@0;1&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/css/site.css" />
</head>
<body class="bg-cream text-ink min-h-screen relative" style="background-image:url('/images/safwan-thottoli-ZOjLtBNuY2E-unsplash.jpg');background-size:cover;background-position:center;background-attachment:fixed;">
  <div style="position:fixed;inset:0;background:rgba(255,255,255,0.75);pointer-events:none;"></div>
  <header class="border-b border-border relative z-10">
    <div class="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between">
      <a href="/" class="flex items-center gap-3 no-underline">
        <div class="w-8 h-8 bg-terra rounded-lg flex items-center justify-center">
          <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
        </div>
        <span class="font-display text-2xl tracking-tight">Agora</span>
      </a>
      {authBlock}
    </div>
  </header>
  <main class="max-w-5xl mx-auto px-6 py-10 relative z-10">
    {messageHtml}
    {body}
  </main>
  <footer class="max-w-5xl mx-auto px-6 py-6 border-t border-border mt-8 relative z-10">
    <div class="flex items-center justify-between gap-4 text-xs text-ink-muted">
      <a href="https://github.com/aduggleby/agora" target="_blank" rel="noreferrer" class="hover:text-ink transition-colors">Agora</a>
      <a href="https://github.com/aduggleby" target="_blank" rel="noreferrer" class="hover:text-ink transition-colors">Made by Alex Duggleby</a>
    </div>
  </footer>
  {RenderCsrfClientScript()}
</body>
</html>
""";
}

static string Html(string? value)
{
    return System.Net.WebUtility.HtmlEncode(value ?? string.Empty);
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
