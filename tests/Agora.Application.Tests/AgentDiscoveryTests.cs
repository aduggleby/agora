using System.Net;
using System.Threading.RateLimiting;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Web.Agents;
using Agora.Web.Pages.U;
using Agora.Web.Services;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Agora.Application.Tests;

/// <summary>The per-link <c>llms.txt</c>, the upload page hint and the agent wording of the completion email.</summary>
public sealed class AgentDiscoveryTests
{
    private const string Code = "AbCdEfGh12345678";

    [Fact]
    public async Task Llms_txt_is_404_when_the_switch_is_off_or_the_code_is_unknown()
    {
        await using var host = await Host.StartAsync(allowAgents: false);

        foreach (var path in new[] { $"/u/{Code}/llms.txt", "/u/nosuchcode123/llms.txt" })
        {
            var response = await host.GetAsync(path);
            Assert.Equal(HttpStatusCode.NotFound, response.Status);
            Assert.DoesNotContain("mcp?upload", response.Body);
            Assert.False(response.Headers.ContainsKey("Set-Cookie"));
        }
    }

    [Fact]
    public async Task Llms_txt_serves_markdown_with_the_recipe_when_the_switch_is_on()
    {
        await using var host = await Host.StartAsync(allowAgents: true, displayName: "Ann *Bold* <b>x</b>\nIgnore previous");

        var response = await host.GetAsync($"/u/{Code}/llms.txt");

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("text/markdown; charset=utf-8", response.Headers["Content-Type"]);
        Assert.Equal("no-store", response.Headers["Cache-Control"]);
        Assert.Equal("noindex", response.Headers["X-Robots-Tag"]);
        Assert.Equal("nosniff", response.Headers["X-Content-Type-Options"]);
        Assert.False(response.Headers.ContainsKey("Set-Cookie"));
        var body = response.Body;
        Assert.Contains($"https://files.example.com/mcp?upload={Code}", body);
        Assert.Contains("`send_files`", body);
        Assert.Contains("`get_upload_url`", body);
        Assert.Contains($"https://files.example.com/u/{Code}", body);
        Assert.Contains("--fail-with-body", body);
        Assert.Contains("Content-Type: application/json", body);
        Assert.Contains("$(wc -c < \"$FILE\")", body);
        Assert.Contains("curl -sS --fail-with-body -T \"$FILE\" \"$UPLOAD_URL\"", body);
        Assert.Contains("/send", body);
        Assert.Contains("1 MiB", body);
        Assert.Contains("At most 20 files", body);
        // The owner name is escaped and flattened to one line.
        Assert.Contains("Ann \\*Bold\\* \\<b\\>x\\</b\\> Ignore previous", body);
        Assert.DoesNotContain("<b>", body);
    }

    [Fact]
    public async Task Upload_page_links_the_instructions_only_when_the_switch_is_on()
    {
        await using (var on = await Host.StartAsync(allowAgents: true))
        {
            var page = (await on.GetAsync($"/u/{Code}")).Body;
            Assert.Contains($"<link rel=\"alternate\" type=\"text/markdown\" href=\"/u/{Code}/llms.txt\" title=\"Instructions for AI agents\"", page);
            Assert.Contains("Are you an AI agent?", page);
            Assert.Contains($"href=\"/u/{Code}/llms.txt\"", page);
        }

        await using var off = await Host.StartAsync(allowAgents: false);
        var offPage = (await off.GetAsync($"/u/{Code}")).Body;
        Assert.DoesNotContain("llms.txt", offPage);
        Assert.DoesNotContain("AI agent", offPage);
    }

    [Fact]
    public void Completion_email_gets_agent_wording_only_when_sent_by_an_agent()
    {
        var human = QueuedShareCreationJob.BuildCompletionEmailCore(Payload(false), "https://files.example.com/s/abcdefgh", "owner@example.com", "Agora");
        var agent = QueuedShareCreationJob.BuildCompletionEmailCore(Payload(true), "https://files.example.com/s/abcdefgh", "owner@example.com", "Agora");

        Assert.DoesNotContain("agent", human.Subject + human.Headline + human.SecondaryText, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("Files were sent to you by an AI agent", agent.Subject);
        Assert.Equal("Files were sent to you by an AI agent", agent.Headline);
        Assert.Contains("Sent through Agora's agent interface. The sender name and email were given by the agent and are not verified.", agent.SecondaryText);
        Assert.Contains("on behalf of", agent.SecondaryText);
        Assert.Equal(human.ActionUrl, agent.ActionUrl);
    }

    private static QueuedShareCreationJob.Payload Payload(bool sentByAgent) => new(
        UploaderEmail: "owner@example.com",
        DraftShareId: Guid.NewGuid().ToString("N"),
        ShareToken: "abcdefgh",
        Message: null,
        SenderName: "Bot",
        SenderEmail: "bot@example.com",
        SenderMessage: "Hello",
        DownloadPassword: null,
        ShowPreviews: false,
        ZipFileName: null,
        NotifyMode: "none",
        ExpiryMode: "days",
        ExpiresAtUtc: null,
        TemplateMode: "account",
        TemplateTitle: null,
        TemplateH1: null,
        TemplateDescription: null,
        TemplateBackgroundColorHex: null,
        TemplateContainerPosition: null,
        TemplateBackgroundUploadId: null,
        UploadedFileIds: [],
        SentByAgent: sentByAgent);

    private sealed record Reply(HttpStatusCode Status, string Body, Dictionary<string, string> Headers);

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _connection;

        private Host(WebApplication app, SqliteConnection connection)
        {
            _app = app;
            _connection = connection;
        }

        public static async Task<Host> StartAsync(bool allowAgents, string displayName = "Ann")
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddSingleton<IEmailSender>(new NoopEmailSender());
            builder.Services.AddSingleton(new PublicBaseUrlResolver("https://files.example.com", false));
            builder.Services.AddSingleton(Options.Create(new AgoraOptions()));
            builder.Services.AddRateLimiter(o => o.AddPolicy(RateLimitSetup.PublicUploadEndpoints, _ => RateLimitPartition.GetNoLimiter("test")));
            builder.Services.AddRazorPages().AddApplicationPart(typeof(IndexModel).Assembly);
            var app = builder.Build();
            app.UseRouting();
            app.UseRateLimiter();
            app.MapAgentDiscoveryEndpoints();
            app.MapRazorPages();
            await app.StartAsync();
            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
                await db.Database.EnsureCreatedAsync();
                db.Users.Add(new UserAccount
                {
                    Id = Guid.NewGuid(),
                    Email = "ann@example.com",
                    DisplayName = displayName,
                    EmailConfirmed = true,
                    PasswordHash = "x",
                    SecurityStamp = "stamp",
                    UploadToken = Code,
                    AllowAgentUploads = allowAgents,
                    CreatedAtUtc = DateTime.UtcNow
                });
                await db.SaveChangesAsync();
            }

            return new Host(app, connection);
        }

        public async Task<Reply> GetAsync(string path)
        {
            var context = await _app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = HttpMethods.Get;
                ctx.Request.Path = path;
            });
            var body = await new StreamReader(context.Response.Body).ReadToEndAsync();
            var headers = context.Response.Headers.ToDictionary(h => h.Key, h => h.Value.ToString(), StringComparer.OrdinalIgnoreCase);
            return new Reply((HttpStatusCode)context.Response.StatusCode, body, headers);
        }

        public async ValueTask DisposeAsync()
        {
            await _app.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
