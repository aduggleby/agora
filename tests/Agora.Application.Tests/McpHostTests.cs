using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Auth;
using Agora.Web.Endpoints;
using Agora.Web.Services;
using Agora.Web.Startup;
using Hangfire;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Agora.Web.Agents;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Agora.Application.Tests;

/// <summary>Email sender for test hosts that only need <c>AuthService</c> to be constructible.</summary>
internal sealed class TestEmailSender : IEmailSender
{
    public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
    public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>
/// The <c>/mcp</c> endpoint over a TestServer with the real authentication wiring, policies, rate limiter and the
/// official MCP client: challenge, caller modes, tool sets per caller, Origin check and the rate-limit rules. The
/// tool bodies are not wired to services yet; these tests only cover what does not need them.
/// </summary>
public sealed class McpHostTests
{
    private const string Base = "https://files.example.test";
    private const string MetadataUrl = Base + "/.well-known/oauth-protected-resource/mcp";
    private static readonly string[] OwnerToolNames = ["upload_file", "get_upload_url", "create_share", "get_share", "list_shares", "delete_share"];
    private const string Initialize = """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}""";

    [Fact]
    public async Task Bare_mcp_is_challenged_with_the_resource_metadata_url_and_api_v1_stays_unchanged()
    {
        await using var host = await Host.StartAsync();

        var mcp = await host.PostMcpAsync("/mcp");
        var api = await host.SendAsync(HttpMethod.Get, "/api/v1/me");

        Assert.Equal(HttpStatusCode.Unauthorized, mcp.StatusCode);
        Assert.Equal($"Bearer resource_metadata=\"{MetadataUrl}\"", mcp.Headers.WwwAuthenticate.ToString());
        Assert.Equal("no-store", mcp.Headers.CacheControl!.ToString());
        Assert.Equal(HttpStatusCode.Unauthorized, api.StatusCode);
        Assert.Equal("Bearer", api.Headers.WwwAuthenticate.ToString());
    }

    [Theory]
    [InlineData("agora_pat_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
    [InlineData("garbage")]
    public async Task Invalid_bearer_is_invalid_token_with_the_resource_metadata_url(string bearer)
    {
        await using var host = await Host.StartAsync();

        var response = await host.PostMcpAsync("/mcp", bearer: bearer);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal($"Bearer error=\"invalid_token\", resource_metadata=\"{MetadataUrl}\"", response.Headers.WwwAuthenticate.ToString());
    }

    [Theory]
    [InlineData("?upload=")]
    [InlineData("?upload=%20")]
    [InlineData("?upload=a&upload=b")]
    [InlineData("?other=a")]
    public async Task Missing_or_ambiguous_upload_query_without_a_bearer_is_challenged(string query)
    {
        await using var host = await Host.StartAsync();

        var response = await host.PostMcpAsync("/mcp" + query);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("resource_metadata", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task A_bearer_wins_over_an_upload_query()
    {
        await using var host = await Host.StartAsync();

        var response = await host.PostMcpAsync("/mcp?upload=abc", bearer: "agora_pat_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Capture_token_is_forbidden()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueCaptureTokenAsync();

        var response = await host.PostMcpAsync("/mcp", bearer: token);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_caller_lists_exactly_the_two_upload_link_tools()
    {
        await using var host = await Host.StartAsync();
        await using var client = await host.ConnectAsync("/mcp?upload=Ab12cd34");

        var tools = await client.ListToolsAsync();

        Assert.Equal(["get_upload_url", "send_files"], tools.Select(x => x.Name).Order(StringComparer.Ordinal));
        Assert.Contains("upload link", client.ServerInstructions);
    }

    private static string ResultText(ModelContextProtocol.Protocol.CallToolResult result) =>
        string.Concat(result.Content.OfType<TextContentBlock>().Select(x => x.Text));

    [Fact]
    public async Task Anonymous_send_files_is_refused_with_the_exact_message_while_the_switch_is_off()
    {
        await using var host = await Host.StartAsync();
        await using var client = await host.ConnectAsync($"/mcp?upload={host.UploadCode}");

        var send = await client.CallToolAsync("send_files", new Dictionary<string, object?>
        {
            ["sender_name"] = "Bot",
            ["sender_email"] = "bot@example.com",
            ["files"] = new object[] { new Dictionary<string, object?> { ["file_name"] = "a.txt", ["text"] = "a" } }
        });
        var url = await client.CallToolAsync("get_upload_url", new Dictionary<string, object?> { ["file_name"] = "a.txt", ["size_bytes"] = 1 });

        var expected = $"Refused (403): The owner of this upload link does not accept uploads from AI agents. A person can still send files at {Base}/u/{host.UploadCode} in a browser.";
        Assert.True(send.IsError);
        Assert.Equal(expected, ResultText(send));
        Assert.True(url.IsError);
        Assert.Equal(expected, ResultText(url));
        Assert.Empty(await host.SharesAsync());
    }

    [Fact]
    public async Task Anonymous_send_files_with_inline_files_creates_a_received_share_sent_by_the_agent()
    {
        await using var host = await Host.StartAsync();
        await host.SetAllowAgentUploadsAsync(true);
        await using var client = await host.ConnectAsync($"/mcp?upload={host.UploadCode}");

        var send = await client.CallToolAsync("send_files", new Dictionary<string, object?>
        {
            ["sender_name"] = "Report Bot",
            ["sender_email"] = "bot@example.com",
            ["message"] = "Weekly report",
            ["files"] = new object[] { new Dictionary<string, object?> { ["file_name"] = "report.txt", ["text"] = "numbers" } }
        });

        Assert.True(send.IsError != true, ResultText(send));
        Assert.Equal("queued", send.StructuredContent!.Value.GetProperty("state").GetString());
        await host.RunQueuedJobAsync();
        var share = Assert.Single(await host.SharesAsync());
        Assert.True(share.SentByAgent);
        Assert.Equal("Report Bot", share.SenderName);
        Assert.Equal("bot@example.com", share.SenderEmail);
        Assert.Equal("Weekly report", share.SenderMessage);
    }

    [Fact]
    public async Task Anonymous_upload_url_then_put_then_send_files_with_the_draft_id_works()
    {
        await using var host = await Host.StartAsync();
        await host.SetAllowAgentUploadsAsync(true);
        await using var client = await host.ConnectAsync($"/mcp?upload={host.UploadCode}");

        var issued = (await client.CallToolAsync("get_upload_url", new Dictionary<string, object?> { ["file_name"] = "big.bin", ["size_bytes"] = 4 })).StructuredContent!.Value;
        var put = await host.PutAsync(new Uri(issued.GetProperty("uploadUrl").GetString()!).AbsolutePath, [1, 2, 3, 4]);
        Assert.Equal(HttpStatusCode.Created, put.StatusCode);

        var send = await client.CallToolAsync("send_files", new Dictionary<string, object?>
        {
            ["sender_name"] = "Bot",
            ["sender_email"] = "bot@example.com",
            ["draft_id"] = issued.GetProperty("draftId").GetString()
        });

        Assert.True(send.IsError != true, ResultText(send));
        await host.RunQueuedJobAsync();
        Assert.True(Assert.Single(await host.SharesAsync()).SentByAgent);
    }

    [Fact]
    public async Task Anonymous_send_files_refuses_a_client_chosen_draft_id_and_takes_the_code_only_from_the_query()
    {
        await using var host = await Host.StartAsync();
        await host.SetAllowAgentUploadsAsync(true);
        await using var client = await host.ConnectAsync($"/mcp?upload={host.UploadCode}");

        var chosen = await client.CallToolAsync("send_files", new Dictionary<string, object?>
        {
            ["sender_name"] = "Bot",
            ["sender_email"] = "bot@example.com",
            ["draft_id"] = "0123456789abcdef0123456789abcdef"
        });
        Assert.True(chosen.IsError);
        Assert.StartsWith("Refused (400): Unknown draftId", ResultText(chosen));

        // The tools have no code parameter: a wrong code in the query is simply an unknown link.
        await using var wrong = await host.ConnectAsync("/mcp?upload=nosuchcode");
        var unknown = await wrong.CallToolAsync("get_upload_url", new Dictionary<string, object?> { ["file_name"] = "a.txt", ["size_bytes"] = 1 });
        Assert.Equal("Refused (404): Upload link not found.", ResultText(unknown));
        var tools = await client.ListToolsAsync();
        Assert.DoesNotContain(tools, t => t.JsonSchema.ToString().Contains("upload_code", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Own_token_lists_the_owner_tools_without_read_share_file_and_all_adds_it()
    {
        await using var host = await Host.StartAsync();
        await using var own = await host.ConnectAsync("/mcp", await host.IssueAgentTokenAsync("own"));
        await using var all = await host.ConnectAsync("/mcp", await host.IssueAgentTokenAsync("all"));

        var ownTools = await own.ListToolsAsync();
        var allTools = await all.ListToolsAsync();

        Assert.Equal(OwnerToolNames.Order(StringComparer.Ordinal), ownTools.Select(x => x.Name).Order(StringComparer.Ordinal));
        Assert.Equal(OwnerToolNames.Append("read_share_file").Order(StringComparer.Ordinal), allTools.Select(x => x.Name).Order(StringComparer.Ordinal));
        Assert.True(ownTools.Single(x => x.Name == "list_shares").ProtocolTool.Annotations!.ReadOnlyHint);
        Assert.True(ownTools.Single(x => x.Name == "delete_share").ProtocolTool.Annotations!.DestructiveHint);
    }

    [Fact]
    public async Task Access_level_changes_apply_to_the_next_session()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueAgentTokenAsync("own");
        await using (var before = await host.ConnectAsync("/mcp", token))
        {
            Assert.DoesNotContain(await before.ListToolsAsync(), x => x.Name == "read_share_file");
        }

        await host.SetLevelAsync(token, "all");

        await using var after = await host.ConnectAsync("/mcp", token);
        Assert.Contains(await after.ListToolsAsync(), x => x.Name == "read_share_file");
    }

    private static string Text(CallToolResult result) => string.Concat(result.Content.OfType<TextContentBlock>().Select(x => x.Text));

    private static JsonElement Structured(CallToolResult result) => result.StructuredContent!.Value;

    private static Dictionary<string, object?> Args(params (string Key, object? Value)[] values) => values.ToDictionary(x => x.Key, x => x.Value);

    private static object[] Inline(params (string Name, string Text)[] files) =>
        files.Select(x => (object)new Dictionary<string, object?> { ["file_name"] = x.Name, ["text"] = x.Text }).ToArray();

    [Fact]
    public async Task Create_share_with_inline_files_returns_a_ready_link_and_the_password_once()
    {
        await using var host = await Host.StartAsync();
        await using var client = await host.ConnectAsync("/mcp", await host.IssueAgentTokenAsync("own"));

        var call = client.CallToolAsync("create_share", Args(
            ("files", Inline(("a.txt", "alpha"), ("b.txt", "beta"))),
            ("expires_at", DateTimeOffset.UtcNow.AddDays(7).ToString("O")),
            ("download_password", "correct horse battery"),
            ("message", "hello"))).AsTask();
        await host.RunQueuedJobAsync();
        var result = await call;

        Assert.True(result.IsError != true, Text(result));
        var view = Structured(result);
        Assert.True(view.GetProperty("ready").GetBoolean());
        Assert.Equal("completed", view.GetProperty("state").GetString());
        Assert.Equal("correct horse battery", view.GetProperty("password").GetString());
        Assert.StartsWith($"{Base}/s/", view.GetProperty("url").GetString());
        Assert.Equal(JsonDocument.Parse(Text(result)).RootElement.GetRawText(), view.GetRawText());
        Assert.EndsWith("Z", view.GetProperty("createdAtUtc").GetString());
        Assert.EndsWith("Z", view.GetProperty("expiresAtUtc").GetString());

        var token = view.GetProperty("token").GetString()!;
        var again = await client.CallToolAsync("get_share", Args(("token", token)));
        var read = Structured(again);
        Assert.False(read.TryGetProperty("password", out _));
        Assert.True(read.GetProperty("passwordProtected").GetBoolean());
        Assert.Equal(["a.txt", "b.txt"], read.GetProperty("files").EnumerateArray().Select(x => x.GetProperty("name").GetString()).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Upload_file_twice_then_create_share_from_the_draft()
    {
        await using var host = await Host.StartAsync();
        await using var client = await host.ConnectAsync("/mcp", await host.IssueAgentTokenAsync("own"));

        var first = Structured(await client.CallToolAsync("upload_file", Args(("file_name", "a.txt"), ("text", "alpha"))));
        var draft = first.GetProperty("draftId").GetString()!;
        var second = Structured(await client.CallToolAsync("upload_file", Args(("file_name", "b.bin"), ("content_base64", Convert.ToBase64String([1, 2, 3])), ("draft_id", draft))));
        var call = client.CallToolAsync("create_share", Args(("draft_id", draft))).AsTask();
        await host.RunQueuedJobAsync();
        var result = await call;

        Assert.Equal(draft, second.GetProperty("draftId").GetString());
        Assert.True(result.IsError != true, Text(result));
        Assert.True(Structured(result).GetProperty("ready").GetBoolean());
    }

    [Fact]
    public async Task Inline_content_over_1_MiB_is_refused_with_the_http_status_text()
    {
        await using var host = await Host.StartAsync();
        await using var client = await host.ConnectAsync("/mcp", await host.IssueAgentTokenAsync("own"));

        var result = await client.CallToolAsync("upload_file", Args(("file_name", "big.txt"), ("text", new string('a', 1024 * 1024 + 1000))));

        Assert.True(result.IsError);
        Assert.StartsWith("Refused (413): ", Text(result));
    }

    [Fact]
    public async Task Refusals_arrive_as_error_results_with_status_and_message()
    {
        await using var host = await Host.StartAsync();
        await using var client = await host.ConnectAsync("/mcp", await host.IssueAgentTokenAsync("own"));

        var both = await client.CallToolAsync("upload_file", Args(("file_name", "a.txt"), ("text", "x"), ("content_base64", "eA==")));
        var noFiles = await client.CallToolAsync("create_share", Args());
        var missing = await client.CallToolAsync("get_share", Args(("token", "doesnotexist")));
        var sizeMismatch = await client.CallToolAsync("get_upload_url", Args(("file_name", "a.txt"), ("size_bytes", 0)));

        Assert.True(both.IsError);
        Assert.StartsWith("Refused (400): ", Text(both));
        Assert.True(noFiles.IsError);
        Assert.Equal("Refused (400): draftId or files is required.", Text(noFiles));
        Assert.True(missing.IsError);
        Assert.Equal("Refused (404): No such share.", Text(missing));
        Assert.True(sizeMismatch.IsError);
        Assert.StartsWith("Refused (400): ", Text(sizeMismatch));
    }

    [Fact]
    public async Task Get_upload_url_returns_a_one_time_url_and_draft()
    {
        await using var host = await Host.StartAsync();
        await using var client = await host.ConnectAsync("/mcp", await host.IssueAgentTokenAsync("own"));

        var result = await client.CallToolAsync("get_upload_url", Args(("file_name", "big.bin"), ("size_bytes", 5_000_000)));

        Assert.True(result.IsError != true, Text(result));
        var info = Structured(result);
        Assert.StartsWith($"{Base}/api/v1/upload-urls/", info.GetProperty("uploadUrl").GetString());
        Assert.False(string.IsNullOrEmpty(info.GetProperty("draftId").GetString()));
    }

    [Fact]
    public async Task Own_level_lists_and_deletes_only_its_shares_and_cannot_read_files_but_all_can()
    {
        await using var host = await Host.StartAsync();
        var ownToken = await host.IssueAgentTokenAsync("own");
        await using var own = await host.ConnectAsync("/mcp", ownToken);
        var mine = await host.CreateViaToolAsync(own, "mine.txt", "mine");
        var browser = await host.SeedBrowserShareAsync();

        var listed = Structured(await own.CallToolAsync("list_shares", Args()));
        var tokens = listed.GetProperty("shares").EnumerateArray().Select(x => x.GetProperty("token").GetString()).ToList();
        var deleteOthers = await own.CallToolAsync("delete_share", Args(("token", browser)));
        var getOthers = await own.CallToolAsync("get_share", Args(("token", browser)));

        Assert.Equal([mine], tokens);
        Assert.True(deleteOthers.IsError);
        Assert.StartsWith("Refused (404): ", Text(deleteOthers));
        Assert.True(getOthers.IsError);

        // Level "all": the same token after the owner raises it. read_share_file appears only in a new session.
        await host.SetLevelAsync(ownToken, "all");
        await using var all = await host.ConnectAsync("/mcp", ownToken);
        var allTokens = Structured(await all.CallToolAsync("list_shares", Args())).GetProperty("shares").EnumerateArray().Select(x => x.GetProperty("token").GetString()).ToList();
        Assert.Contains(browser, allTokens);
        Assert.Contains(mine, allTokens);

        var deleted = await all.CallToolAsync("delete_share", Args(("token", browser)));
        Assert.True(deleted.IsError != true, Text(deleted));
        Assert.True(Structured(deleted).GetProperty("deleted").GetBoolean());
        Assert.DoesNotContain(browser, Structured(await all.CallToolAsync("list_shares", Args())).GetProperty("shares").EnumerateArray().Select(x => x.GetProperty("token").GetString()));
    }

    [Fact]
    public async Task Read_share_file_returns_text_blobs_and_download_urls_and_labels_received_files()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueAgentTokenAsync("all");
        await using var client = await host.ConnectAsync("/mcp", token);
        var share = await host.CreateViaToolAsync(client, "note.txt", "hello world");
        var fileId = await host.FirstFileIdAsync(share);

        var text = await client.CallToolAsync("read_share_file", Args(("token", share), ("file_id", fileId)));

        Assert.True(text.IsError != true, Text(text));
        Assert.Equal("hello world", Text(text));
        Assert.False(Structured(text).TryGetProperty("untrusted", out _) && Structured(text).GetProperty("untrusted").ValueKind == JsonValueKind.True);

        await host.MarkReceivedAsync(share);
        var received = await client.CallToolAsync("read_share_file", Args(("token", share), ("file_id", fileId)));

        Assert.Equal(AgentLimits.UntrustedNotice, ((TextContentBlock)received.Content[0]).Text);
        Assert.Equal("hello world", ((TextContentBlock)received.Content[1]).Text);
        Assert.True(Structured(received).GetProperty("untrusted").GetBoolean());
        var listing = Structured(await client.CallToolAsync("get_share", Args(("token", share))));
        Assert.True(listing.GetProperty("received").GetBoolean());
        Assert.True(listing.GetProperty("untrusted").GetBoolean());
        Assert.Equal(AgentLimits.UntrustedNotice, listing.GetProperty("notice").GetString());

        var blobShare = await host.CreateViaToolAsync(client, "data.bin", base64: Convert.ToBase64String([0xFF, 0x00, 0x10]));
        var blob = await client.CallToolAsync("read_share_file", Args(("token", blobShare), ("file_id", await host.FirstFileIdAsync(blobShare))));
        var embedded = Assert.IsType<EmbeddedResourceBlock>(Assert.Single(blob.Content));
        Assert.Equal(new byte[] { 0xFF, 0x00, 0x10 }, Assert.IsType<BlobResourceContents>(embedded.Resource).DecodedData.ToArray());

        var bigShare = await host.CreateViaToolAsync(client, "big.txt", text: new string('x', 1024 * 1024 + 10), viaUrl: true);
        var big = await client.CallToolAsync("read_share_file", Args(("token", bigShare), ("file_id", await host.FirstFileIdAsync(bigShare))));
        Assert.True(big.IsError != true, Text(big));
        Assert.StartsWith($"{Base}/api/v1/download-urls/", Structured(big).GetProperty("downloadUrl").GetString());
    }

    [Fact]
    public async Task Own_level_cannot_call_read_share_file()
    {
        await using var host = await Host.StartAsync();
        await using var client = await host.ConnectAsync("/mcp", await host.IssueAgentTokenAsync("own"));

        // The tool is not offered at level "own", so the server does not know it.
        await Assert.ThrowsAsync<McpProtocolException>(async () =>
            await client.CallToolAsync("read_share_file", Args(("token", "abc"), ("file_id", Guid.NewGuid().ToString()))));
    }

    [Fact]
    public async Task Foreign_origin_is_refused_with_a_json_rpc_error_and_no_origin_or_the_same_origin_passes()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueAgentTokenAsync("own");

        var foreign = await host.PostMcpAsync("/mcp", bearer: token, origin: "https://evil.example");
        var opaque = await host.PostMcpAsync("/mcp", bearer: token, origin: "null");
        var same = await host.PostMcpAsync("/mcp", bearer: token, origin: Base);
        var none = await host.PostMcpAsync("/mcp", bearer: token);

        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, opaque.StatusCode);
        var body = JsonDocument.Parse(await foreign.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("2.0", body.GetProperty("jsonrpc").GetString());
        Assert.False(body.TryGetProperty("id", out _));
        Assert.True(body.TryGetProperty("error", out _));
        Assert.Equal(HttpStatusCode.OK, same.StatusCode);
        Assert.Equal(HttpStatusCode.OK, none.StatusCode);
    }

    [Fact]
    public async Task Anonymous_mcp_consumes_the_public_upload_bucket_and_token_calls_do_not()
    {
        await using var host = await Host.StartAsync(limits: true);
        var token = await host.IssueAgentTokenAsync("own");

        var tokenStatuses = new List<HttpStatusCode>();
        for (var i = 0; i < 30; i++)
        {
            tokenStatuses.Add((await host.PostMcpAsync("/mcp", bearer: token)).StatusCode);
        }

        var anonymous = new List<HttpResponseMessage>();
        for (var i = 0; i < 27; i++)
        {
            anonymous.Add(await host.PostMcpAsync("/mcp?upload=Ab12cd34"));
        }

        Assert.DoesNotContain(HttpStatusCode.TooManyRequests, tokenStatuses);
        Assert.Equal(25, anonymous.Count(x => x.StatusCode != HttpStatusCode.TooManyRequests));
        Assert.Equal(2, anonymous.Count(x => x.StatusCode == HttpStatusCode.TooManyRequests));
        Assert.True(anonymous[^1].Headers.Contains("Retry-After"));
    }

    [Fact]
    public async Task Anonymous_mcp_shares_its_bucket_with_the_browser_upload_routes()
    {
        await using var host = await Host.StartAsync(limits: true);
        for (var i = 0; i < 25; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, "/test/public-upload")).StatusCode);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, (await host.PostMcpAsync("/mcp?upload=Ab12cd34")).StatusCode);
    }

    [Fact]
    public async Task A_third_concurrent_request_per_account_is_limited_and_the_permit_is_released()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueAgentTokenAsync("own");
        var other = await host.IssueAgentTokenAsync("own");

        var first = host.StartHeldRequest(token);
        var second = host.StartHeldRequest(token);
        await host.WaitHeldAsync(2);
        var third = await host.SendAsync(HttpMethod.Post, "/test/slow-mcp", bearer: token);
        var otherAccountSameUser = await host.SendAsync(HttpMethod.Post, "/test/slow-mcp", bearer: other);
        host.ReleaseHeld();
        await Task.WhenAll(first, second);
        // The permit is returned when the middleware unwinds, which can trail the response by a moment.
        var after = await host.SendAsync(HttpMethod.Post, "/test/slow-mcp", bearer: token);
        for (var attempt = 0; attempt < 50 && after.StatusCode == HttpStatusCode.TooManyRequests; attempt++)
        {
            await Task.Delay(50);
            after = await host.SendAsync(HttpMethod.Post, "/test/slow-mcp", bearer: token);
        }

        // Both tokens belong to one account, so the limit is per account, not per token.
        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, otherAccountSameUser.StatusCode);
        Assert.Equal(HttpStatusCode.OK, after.StatusCode);
    }

    [Fact]
    public async Task Anonymous_concurrency_is_limited_per_address()
    {
        await using var host = await Host.StartAsync();

        var first = host.StartHeldRequest(null, "?upload=Ab12cd34");
        var second = host.StartHeldRequest(null, "?upload=Ab12cd34");
        await host.WaitHeldAsync(2);
        var third = await host.SendAsync(HttpMethod.Post, "/test/slow-mcp?upload=Ab12cd34");
        host.ReleaseHeld();
        await Task.WhenAll(first, second);

        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
    }

    [Fact]
    public async Task Request_body_limit_of_2_MiB_applies_to_mcp()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueAgentTokenAsync("own");

        var tooLarge = await host.PostMcpAsync("/mcp", bearer: token, body: new string('a', 2 * 1024 * 1024 + 1));

        Assert.True(tooLarge.StatusCode is HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.BadRequest, tooLarge.StatusCode.ToString());
    }

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _connection;
        private readonly HttpClient _client;
        private readonly string _storageRoot;
        private readonly Guid _userId;
        private readonly string _stamp;
        private readonly SemaphoreSlim _held = new(0);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private Host(WebApplication app, SqliteConnection connection, string storageRoot, Guid userId, string stamp)
        {
            _app = app;
            _connection = connection;
            _storageRoot = storageRoot;
            _userId = userId;
            _stamp = stamp;
            _client = app.GetTestClient();
        }

        public static async Task<Host> StartAsync(bool limits = false)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-mcp-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var holder = new HeldRequests();
            var jobs = new RecordingJobs();

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.Configure<AgoraOptions>(o => o.StorageRoot = storageRoot);
            builder.Services.AddSingleton<UploadConcurrency>();
            builder.Services.AddSingleton<IObjectStore>(new FileSystemObjectStore(storageRoot));
            builder.Services.AddSingleton<IShareContentStore, ShareContentStore>();
            builder.Services.AddSingleton<IBackgroundJobClient>(jobs);
            builder.Services.Configure<EmailSenderOptions>(_ => { });
            builder.Services.AddSingleton<ShareCreationStatusStore>();
            builder.Services.AddSingleton<ShareProgressBroadcaster>();
            builder.Services.AddScoped<QueuedShareCreationJob>();
            builder.Services.AddSignalR();
            builder.Services.AddSingleton<KeyedAsyncLock>();
            var scratchOptions = new AgoraOptions { StorageRoot = storageRoot, Scratch = { MaxBytes = 0, MinFreeBytes = 0 } };
            builder.Services.AddSingleton(new ScratchSpaceMonitor(scratchOptions, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System));
            builder.Services.AddSingleton<IPublicOriginProvider>(new FixedOrigin());
            builder.Services.AddScoped<Agora.Infrastructure.Services.ShareManager>();
            builder.Services.AddScoped<IEmailSender, TestEmailSender>();
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
            builder.Services.AddScoped<ApiTokenService>();
            builder.Services.AddSingleton(new PublicBaseUrlResolver(Base, allowRequestHostFallback: false));
            builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
            builder.Services.AddAgoraAuthentication(new AgoraAuthOptions(), CookieSecurePolicy.None);
            builder.Services.AddAuthorization(AuthSetup.ConfigureAuthorization);
            builder.Services.AddRateLimiter(o => RateLimitSetup.Configure(o, new AgoraRateLimitOptions { AnonymousPerMinute = 0 }, isE2E: !limits));
            builder.Services.AddAgoraAgents();

            var app = builder.Build();
            app.UseAgoraExceptionHandler();
            app.UseAuthentication();
            app.UseRateLimiter();
            app.UseAuthorization();
            app.MapGet("/test/public-upload", () => "ok").RequireRateLimiting(RateLimitSetup.PublicUploadEndpoints);
            app.MapApiV1Endpoints(captureRequestBodyLimit: 1024 * 1024);
            app.MapAgoraAgents();
            // Stands in for a slow /mcp call: same metadata, policy and limiters, held until released.
            app.MapPost("/test/slow-mcp", async (HttpContext context) =>
            {
                holder.Held.Release();
                await holder.Release.Task.WaitAsync(context.RequestAborted);
                return Results.Ok();
            }).WithMetadata(ApiEndpointMetadata.Instance, McpEndpointMetadata.Instance)
              .RequireAuthorization(ApiTokenDefaults.AgentMcpPolicy)
              .RequireRateLimiting(RateLimitSetup.PublicUploadEndpoints);
            await app.StartAsync();

            var user = TestUsers.Seed(Guid.NewGuid(), "owner@example.com");
            await using (var scope = app.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
                await db.Database.EnsureCreatedAsync();
                db.Users.Add(user);
                await db.SaveChangesAsync();
            }

            var host = new Host(app, connection, storageRoot, user.Id, user.SecurityStamp) { UploadCode = user.UploadToken };
            host._heldHolder = holder;
            host.Jobs = jobs;
            return host;
        }

        private HeldRequests? _heldHolder;

        public RecordingJobs Jobs { get; private set; } = null!;
        public string UploadCode { get; private init; } = string.Empty;

        public async Task SetAllowAgentUploadsAsync(bool allow)
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            (await db.Users.SingleAsync()).AllowAgentUploads = allow;
            await db.SaveChangesAsync();
        }

        public async Task<List<Agora.Domain.Entities.Share>> SharesAsync()
        {
            await using var scope = _app.Services.CreateAsyncScope();
            return await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().Shares.AsNoTracking().ToListAsync();
        }

        public Task<HttpResponseMessage> PutAsync(string path, byte[] body) => _client.PutAsync(path, new ByteArrayContent(body));
        public Guid UserId => _userId;

        public Task<HttpResponseMessage> StartHeldRequest(string? bearer, string query = "") =>
            SendAsync(HttpMethod.Post, "/test/slow-mcp" + query, bearer);

        public async Task WaitHeldAsync(int count)
        {
            for (var i = 0; i < count; i++)
            {
                Assert.True(await _heldHolder!.Held.WaitAsync(TimeSpan.FromSeconds(10)));
            }
        }

        public void ReleaseHeld() => _heldHolder!.Release.TrySetResult();

        /// <summary>Runs the queued share creation like the Hangfire worker would (the tool call waits for it).</summary>
        public async Task RunQueuedJobAsync()
        {
            for (var i = 0; i < 400 && Jobs.Jobs.Count == 0; i++)
            {
                await Task.Delay(25);
            }

            Hangfire.Common.Job job;
            lock (Jobs.Jobs)
            {
                job = Jobs.Jobs[^1];
                Jobs.Jobs.Clear();
            }

            await using var scope = _app.Services.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<QueuedShareCreationJob>().ProcessAsync((QueuedShareCreationJob.Payload)job.Args[0], CancellationToken.None);
        }

        /// <summary>Creates a one-file share through the tools and returns its token.</summary>
        public async Task<string> CreateViaToolAsync(McpClient client, string name, string? text = null, string? base64 = null, bool viaUrl = false)
        {
            var args = new Dictionary<string, object?>();
            if (viaUrl)
            {
                var bytes = Encoding.UTF8.GetBytes(text!);
                var issued = (await client.CallToolAsync("get_upload_url", new Dictionary<string, object?> { ["file_name"] = name, ["size_bytes"] = bytes.Length })).StructuredContent!.Value;
                var put = await _client.PutAsync(new Uri(issued.GetProperty("uploadUrl").GetString()!).AbsolutePath, new ByteArrayContent(bytes));
                Assert.Equal(HttpStatusCode.Created, put.StatusCode);
                args["draft_id"] = issued.GetProperty("draftId").GetString();
            }
            else
            {
                args["files"] = new object[] { new Dictionary<string, object?> { ["file_name"] = name, ["text"] = text, ["content_base64"] = base64 } };
            }

            var call = client.CallToolAsync("create_share", args).AsTask();
            await RunQueuedJobAsync();
            var result = await call;
            Assert.True(result.IsError != true, string.Concat(result.Content.OfType<TextContentBlock>().Select(x => x.Text)));
            return result.StructuredContent!.Value.GetProperty("token").GetString()!;
        }

        public async Task<string> FirstFileIdAsync(string shareToken)
        {
            await using var scope = _app.Services.CreateAsyncScope();
            return (await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().ShareFiles.AsNoTracking().Where(x => x.Share.ShareToken == shareToken).Select(x => x.Id).FirstAsync()).ToString();
        }

        public async Task MarkReceivedAsync(string shareToken)
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            var share = await db.Shares.SingleAsync(x => x.ShareToken == shareToken);
            share.SenderName = "Sender";
            share.SenderEmail = "sender@example.com";
            share.SenderMessage = "hello";
            await db.SaveChangesAsync();
        }

        /// <summary>A share created in the browser (no agent token behind it).</summary>
        public async Task<string> SeedBrowserShareAsync()
        {
            var token = TokenCodec.GenerateAlphanumericToken(10);
            await using var scope = _app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            db.Shares.Add(new Agora.Domain.Entities.Share
            {
                Id = Guid.NewGuid(),
                OwnerUserId = _userId,
                UploaderEmail = "owner@example.com",
                ShareToken = token,
                ZipDisplayName = "a.zip",
                AccessMode = ShareModes.ToStorageValue(ShareAccessMode.DownloadOnly),
                ShareExperienceType = ShareModes.ToStorageValue(ShareExperienceType.Archive),
                NotifyMode = "none",
                CreatedAtUtc = DateTime.UtcNow,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            await db.SaveChangesAsync();
            return token;
        }

        public async Task<string> IssueAgentTokenAsync(string level)
        {
            await using var scope = _app.Services.CreateAsyncScope();
            return (await scope.ServiceProvider.GetRequiredService<ApiTokenService>()
                .CreateAgentTokenAsync(_userId, _stamp, "Test agent", level, CancellationToken.None))!;
        }

        public async Task<string> IssueCaptureTokenAsync()
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var tokens = scope.ServiceProvider.GetRequiredService<ApiTokenService>();
            var code = (await tokens.CreatePendingAsync(_userId, _stamp, ApiTokens.CaptureClientId, "Mac", ApiTokenServiceTests.Challenge, ApiTokenServiceTests.Redirect, CancellationToken.None))!;
            return (await tokens.ExchangeAsync(code, ApiTokenServiceTests.Verifier, ApiTokenServiceTests.Redirect, ApiTokens.CaptureClientId, CancellationToken.None)).AccessToken!;
        }

        public async Task SetLevelAsync(string token, string level)
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var tokens = scope.ServiceProvider.GetRequiredService<ApiTokenService>();
            var identity = (await tokens.ValidateAsync(token, CancellationToken.None))!;
            Assert.True(await tokens.SetAccessLevelAsync(identity.TokenId, _userId, level, CancellationToken.None));
        }

        public async Task<McpClient> ConnectAsync(string path, string? bearer = null)
        {
            var http = _app.GetTestClient();
            if (bearer is not null)
            {
                http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            }

            var transport = new HttpClientTransport(new HttpClientTransportOptions { Endpoint = new Uri(Base + path) }, http, ownsHttpClient: true);
            return await McpClient.CreateAsync(transport);
        }

        public Task<HttpResponseMessage> PostMcpAsync(string path, string? bearer = null, string? origin = null, string? body = null) =>
            SendAsync(HttpMethod.Post, path, bearer, origin, new StringContent(body ?? Initialize, Encoding.UTF8, "application/json"), mcp: true);

        public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string? bearer = null, string? origin = null, HttpContent? content = null, bool mcp = false)
        {
            using var request = new HttpRequestMessage(method, path) { Content = content };
            if (bearer is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            }

            if (origin is not null)
            {
                request.Headers.Add("Origin", origin);
            }

            if (mcp)
            {
                request.Headers.Accept.ParseAdd("application/json");
                request.Headers.Accept.ParseAdd("text/event-stream");
            }

            return await _client.SendAsync(request);
        }

        public async ValueTask DisposeAsync()
        {
            _heldHolder?.Release.TrySetResult();
            await _app.DisposeAsync();
            await _connection.DisposeAsync();
            if (Directory.Exists(_storageRoot))
            {
                Directory.Delete(_storageRoot, recursive: true);
            }
        }
    }

    private sealed class HeldRequests
    {
        public SemaphoreSlim Held { get; } = new(0);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed class RecordingJobs : IBackgroundJobClient
    {
        public List<Hangfire.Common.Job> Jobs { get; } = [];

        public string Create(Hangfire.Common.Job job, Hangfire.States.IState state)
        {
            lock (Jobs)
            {
                Jobs.Add(job);
            }

            return Guid.NewGuid().ToString("N");
        }

        public bool ChangeState(string jobId, Hangfire.States.IState state, string expectedState) => true;
    }

    private sealed class FixedOrigin : IPublicOriginProvider
    {
        public string? ConfiguredOrigin => Base;
    }
}
