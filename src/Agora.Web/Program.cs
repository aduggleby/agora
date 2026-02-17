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
var isDevelopment = app.Environment.IsDevelopment();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
    db.Database.EnsureCreated();
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
}

app.UseStaticFiles();
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

if (isDevelopment)
{
    app.MapPost("/login/development", async (HttpContext httpContext, AuthService authService, CancellationToken ct) =>
    {
        var result = await authService.EnsureDevelopmentUserAsync(ct);
        await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CreatePrincipal(result.User));
        return Results.Redirect("/");
    });
}

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

    var adminPanel = isAdmin
        ? """
<div class="bg-cream-dark/60 rounded-xl p-4 mb-8 flex items-center justify-between">
  <div class="flex items-center gap-2">
    <svg class="w-4 h-4 text-ink-muted" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
    <span class="text-sm text-ink-light">Admin</span>
  </div>
  <div class="flex items-center gap-4">
    <a href="/admin" class="text-sm text-terra hover:underline">Manage users</a>
    <a href="/hangfire" class="text-sm text-terra hover:underline">Hangfire</a>
  </div>
</div>
"""
        : string.Empty;

    var body = $"""
<section class="mb-10">
  <h2 class="font-display text-4xl tracking-tight mb-1">Share files,<br><span class="text-terra italic">simply.</span></h2>
  <p class="text-ink-muted text-sm mt-3 max-w-md">Upload files, get a link. Recipients see a branded landing page before downloading.</p>
</section>

{adminPanel}

<section class="mb-10">
  <div class="bg-white rounded-2xl border border-border p-6">
    <h3 class="font-display text-xl mb-4">Create share</h3>
    <form action="/api/shares" method="post" enctype="multipart/form-data" class="space-y-5">
      <div>
        <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Files</label>
        <input type="file" name="files" multiple required class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all file:mr-3 file:py-1 file:px-3 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-terra file:text-white" />
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
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Expiry mode</label>
          <select name="expiryMode" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all appearance-none">
            <option value="date">Date</option>
            <option value="indefinite">Indefinite</option>
          </select>
        </div>
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Expires at (UTC)</label>
          <input type="datetime-local" name="expiresAtUtc" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
        </div>
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Download notifications</label>
          <select name="notifyMode" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all appearance-none">
            <option value="none">None</option>
            <option value="once">First download only</option>
            <option value="every_time">Every download</option>
          </select>
        </div>
      </div>

      <details class="group">
        <summary class="text-sm text-terra font-medium cursor-pointer select-none">Landing page options</summary>
        <div class="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Template mode</label>
            <select name="templateMode" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all appearance-none">
              <option value="account_default">Use account default</option>
              <option value="per_upload">Custom for this share</option>
            </select>
          </div>
          <div>
            <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Title</label>
            <input name="template.title" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
          </div>
          <div>
            <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Heading</label>
            <input name="template.h1" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
          </div>
          <div>
            <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Description</label>
            <input name="template.description" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
          </div>
          <div class="sm:col-span-2">
            <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Background image URL</label>
            <input name="template.backgroundImageUrl" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
          </div>
        </div>
      </details>

      <div class="flex justify-end">
        <button type="submit" class="px-6 py-2.5 bg-terra text-white text-sm font-medium rounded-lg hover:bg-terra/90 transition-colors">Create share link</button>
      </div>
    </form>
  </div>
</section>

<section class="mb-10">
  <div class="bg-white rounded-2xl border border-border p-6">
    <h3 class="font-display text-xl mb-4">Default landing page template</h3>
    <form action="/api/account/template" method="post" class="space-y-4">
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Title</label>
          <input name="title" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" placeholder="Shared file" />
        </div>
        <div>
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Heading</label>
          <input name="h1" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" placeholder="A file was shared with you" />
        </div>
        <div class="sm:col-span-2">
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Description</label>
          <input name="description" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" placeholder="Use the button below to download your file." />
        </div>
        <div class="sm:col-span-2">
          <label class="text-xs font-medium text-ink-muted uppercase tracking-wider mb-1.5 block">Background image URL</label>
          <input name="backgroundImageUrl" class="w-full px-3 py-2 text-sm border border-border rounded-lg bg-cream focus:outline-none focus:border-terra focus:ring-1 focus:ring-terra/20 transition-all" />
        </div>
      </div>
      <div class="flex justify-end">
        <button type="submit" class="px-6 py-2.5 bg-ink text-white text-sm font-medium rounded-lg hover:bg-ink/80 transition-colors">Save template</button>
      </div>
    </form>
  </div>
</section>
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
        var statusDot = user.IsEnabled
            ? """<span class="inline-block w-2 h-2 rounded-full bg-sage"></span>"""
            : """<span class="inline-block w-2 h-2 rounded-full bg-ink-muted"></span>""";

        var roleForm = $"""
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
  <h2 class="font-display text-3xl tracking-tight">Admin</h2>
  <p class="text-ink-muted text-sm mt-1">Manage users, registration, and background jobs.</p>
  <div class="flex items-center gap-4 mt-4">
    <a href="/hangfire" class="text-sm text-terra hover:underline">Open Hangfire Dashboard</a>
    <a href="/" class="text-sm text-ink-muted hover:text-ink">Back to dashboard</a>
  </div>
</section>

<section class="mb-8">
  <div class="bg-white rounded-2xl border border-border p-6">
    <div class="flex items-center justify-between mb-4">
      <h3 class="font-display text-xl">Registration policy</h3>
      <span class="text-xs bg-{(allowRegistration ? "sage-wash text-sage" : "cream-dark text-ink-muted")} px-2 py-0.5 rounded-md">{(allowRegistration ? "Open" : "Closed")}</span>
    </div>
    <form method="post" action="/admin/settings/registration">
      <input type="hidden" name="enabled" value="{(!allowRegistration).ToString().ToLowerInvariant()}" />
      <button type="submit" class="px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-cream-dark transition-colors">{(allowRegistration ? "Disable" : "Enable")} new user registration</button>
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
        : $"""<p class="text-sm text-ink-light mt-4 p-3 bg-cream-dark rounded-lg"><span class="font-medium text-ink">Message:</span> {Html(share.UploaderMessage)}</p>""";

    var bgStyle = string.IsNullOrWhiteSpace(share.BackgroundImageUrl)
        ? ""
        : $"background-image:url('{Html(share.BackgroundImageUrl)}');background-size:cover;background-position:center;";

    var sizeDisplay = share.ZipSizeBytes >= 1024 * 1024
        ? $"{share.ZipSizeBytes / (1024.0 * 1024.0):F1} MB"
        : $"{share.ZipSizeBytes / 1024.0:F0} KB";

    var html = $$"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{Html(share.PageTitle)}}</title>
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

    <div style="margin-top:1.5rem;">
      <a href="/s/{{token}}/download" class="btn">Download</a>
    </div>

    <p style="color:var(--ink-muted);font-size:0.6875rem;margin-top:1.5rem;text-align:center;">Shared via Agora</p>
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

    var messageHtml = string.IsNullOrWhiteSpace(message)
        ? string.Empty
        : $"""<div class="mb-6 px-4 py-3 bg-terra-wash border border-terra-light/30 rounded-xl text-sm text-ink-light">{Html(message)}</div>""";

    var authBlock = string.IsNullOrWhiteSpace(email)
        ? string.Empty
        : $"""
<nav class="flex items-center gap-6">
  <a href="/" class="text-sm text-ink-muted hover:text-ink transition-colors">Shares</a>
  <a href="#template-section" class="text-sm text-ink-muted hover:text-ink transition-colors">Template</a>
  {(isAdmin ? """<a href="/admin" class="text-sm text-ink-muted hover:text-ink transition-colors">Admin</a>""" : "")}
  <div class="w-px h-5 bg-border"></div>
  <div class="flex items-center gap-3">
    <div class="flex items-center gap-2">
      <div class="w-7 h-7 rounded-full bg-terra-wash text-terra text-xs font-medium flex items-center justify-center">{Html(email.Substring(0, 1).ToUpperInvariant())}</div>
      <span class="text-sm text-ink-light">{Html(email)}</span>
    </div>
    <form method="post" action="/logout" class="inline">
      <button type="submit" class="text-xs text-ink-muted hover:text-terra transition-colors">Sign out</button>
    </form>
  </div>
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
<body class="bg-cream text-ink min-h-screen">
  <header class="border-b border-border">
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
  <main class="max-w-5xl mx-auto px-6 py-10">
    {messageHtml}
    {body}
  </main>
  <footer class="max-w-5xl mx-auto px-6 py-6 border-t border-border mt-8">
    <p class="text-xs text-ink-muted">Agora &middot; Self-hosted file sharing</p>
  </footer>
</body>
</html>
""";
}

static string Html(string? value)
{
    return System.Net.WebUtility.HtmlEncode(value ?? string.Empty);
}
