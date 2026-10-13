using System.Net;
using System.Security.Claims;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Pages;
using Agora.Web.Services;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Agora.Application.Tests;

/// <summary>
/// Old links of the form /shares/created?token=... (browser history, earlier emails) still work for the owner, who is
/// redirected to the route form; any other token answers 404.
/// </summary>
public sealed class SharesCreatedCompatRouteTests
{
    private static readonly Guid OwnerId = Guid.NewGuid();
    private const string OwnerEmail = "owner@example.com";

    [Fact]
    public async Task Query_token_links_redirect_the_owner_and_404_everyone_else()
    {
        var storageRoot = Path.Combine(Path.GetTempPath(), "agora-created-compat-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(storageRoot);
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.Configure<AgoraOptions>(o => o.StorageRoot = storageRoot);
        builder.Services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
        builder.Services.AddSingleton<IObjectStore>(new FileSystemObjectStore(storageRoot));
        builder.Services.AddSingleton<IShareContentStore, ShareContentStore>();
        builder.Services.AddSingleton<IBackgroundJobClient, NoopJobClient>();
        builder.Services.AddSingleton<KeyedAsyncLock>();
        builder.Services.AddSingleton(new ScratchSpaceMonitor(new AgoraOptions { StorageRoot = storageRoot }, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System));
        builder.Services.AddScoped<ShareManager>();
        builder.Services.AddSingleton<ShareCreationStatusStore>();
        builder.Services.AddSingleton(new PublicBaseUrlResolver("https://files.example.com", allowRequestHostFallback: false));
        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
        builder.Services.AddRazorPages().AddApplicationPart(typeof(ForgotPasswordModel).Assembly);
        await using var app = builder.Build();
        // Both explicitly, in order: with only UseAuthentication called, WebApplication would insert UseAuthorization
        // ahead of it and the [Authorize] page would see an anonymous user.
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapRazorPages();
        app.MapGet("/test/signin", async (HttpContext ctx) =>
        {
            var identity = new ClaimsIdentity(
                [new Claim(ClaimTypes.NameIdentifier, OwnerId.ToString()), new Claim(ClaimTypes.Email, OwnerEmail), new Claim(ClaimTypes.Name, OwnerEmail)],
                CookieAuthenticationDefaults.AuthenticationScheme);
            await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
            return Results.Ok();
        });
        await app.StartAsync();

        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            await db.Database.EnsureCreatedAsync();
            db.Shares.Add(NewShare("compat123", OwnerId, OwnerEmail));
            db.Shares.Add(NewShare("foreign12", Guid.NewGuid(), "other@example.com"));
            await db.SaveChangesAsync();
        }

        var server = app.GetTestServer();
        var signIn = await server.SendAsync(ctx => { ctx.Request.Method = HttpMethods.Get; ctx.Request.Path = "/test/signin"; });
        var cookie = string.Join("; ", signIn.Response.Headers.SetCookie.Select(v => (v ?? string.Empty).Split(';')[0]));

        async Task<HttpContext> GetAsync(string pathAndQuery)
        {
            var uri = new Uri("http://localhost" + pathAndQuery);
            return await server.SendAsync(ctx =>
            {
                ctx.Request.Method = HttpMethods.Get;
                ctx.Request.Path = uri.AbsolutePath;
                ctx.Request.QueryString = new QueryString(uri.Query);
                ctx.Request.Headers.Cookie = cookie;
            });
        }

        var owned = await GetAsync("/shares/created?token=compat123");
        Assert.Equal((int)HttpStatusCode.Redirect, owned.Response.StatusCode);
        Assert.Equal("/shares/created/compat123", owned.Response.Headers.Location.ToString());

        Assert.Equal((int)HttpStatusCode.NotFound, (await GetAsync("/shares/created?token=foreign12")).Response.StatusCode);
        Assert.Equal((int)HttpStatusCode.NotFound, (await GetAsync("/shares/created?token=nothere1")).Response.StatusCode);
        Assert.Equal((int)HttpStatusCode.NotFound, (await GetAsync("/shares/created")).Response.StatusCode);

        var routeForm = await GetAsync("/shares/created/compat123");
        Assert.Equal((int)HttpStatusCode.OK, routeForm.Response.StatusCode);
        Assert.Equal("same-origin", routeForm.Response.Headers["Referrer-Policy"].ToString());
    }

    private static Share NewShare(string token, Guid ownerId, string email) => new()
    {
        Id = Guid.NewGuid(),
        OwnerUserId = ownerId,
        UploaderEmail = email,
        ShareToken = token,
        ZipDisplayName = "files.zip",
        ZipDiskPath = "zips/2026/10/archive.zip",
        CreatedAtUtc = DateTime.UtcNow,
    };

    private sealed class NoopJobClient : IBackgroundJobClient
    {
        public string Create(Job job, IState state) => Guid.NewGuid().ToString("N");
        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }
}
