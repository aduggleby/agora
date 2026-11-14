using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Agora.Web.Agents;
using Host = Agora.Application.Tests.AgentApiHostTests.Host;

namespace Agora.Application.Tests;

/// <summary>The anonymous agent API of an upload link: switch and code order, server-issued drafts, limits, tickets and sends.</summary>
public sealed class AgentUploadLinkHostTests
{
    private const string UnknownText = "Upload link not found.";
    private static string DisabledText(string code) =>
        $"The owner of this upload link does not accept uploads from AI agents. A person can still send files at https://files.example.test/u/{code} in a browser.";

    private static string Api(Host host, string suffix = "") => $"/api/v1/upload-links/{host.UploadCode}{suffix}";

    private static object Sender => new { senderName = "Report Bot", senderEmail = "bot@example.com", message = "Weekly report" };

    private static async Task<string> ErrorAsync(HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString()!;

    [Fact]
    public async Task Describe_names_the_recipient_and_limits_when_the_switch_is_on()
    {
        await using var host = await Host.StartAsync();

        var response = await host.SendAsync(HttpMethod.Get, Api(host), null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("acceptsAgentUploads").GetBoolean());
        Assert.Equal(1_048_576, body.GetProperty("limits").GetProperty("inlineMaxBytes").GetInt32());
        Assert.Empty(response.Headers.Where(x => x.Key == "Set-Cookie"));
    }

    [Fact]
    public async Task Unknown_code_is_404_on_every_route_before_anything_else()
    {
        await using var host = await Host.StartAsync();
        const string path = "/api/v1/upload-links/nosuchcode";

        foreach (var response in new HttpResponseMessage[]
        {
            await host.SendAsync(HttpMethod.Get, path, null),
            await host.PostAnonymousAsync(path + "/uploads", new { fileName = "a.txt", text = "a" }),
            await host.PostAnonymousAsync(path + "/upload-urls", new { fileName = "a.txt", sizeBytes = 1 }),
            // Not even JSON: the code is resolved before the content type is looked at.
            await host.SendAsync(HttpMethod.Post, path + "/send", null, new StringContent("x", Encoding.UTF8, "text/plain"))
        })
        {
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal(UnknownText, await ErrorAsync(response));
        }
    }

    [Fact]
    public async Task Switch_off_is_403_with_the_exact_message_on_every_route_including_a_ticket_issued_earlier()
    {
        await using var host = await Host.StartAsync();
        var issued = await (await host.PostAnonymousAsync(Api(host, "/upload-urls"), new { fileName = "a.txt", sizeBytes = 3 })).Content.ReadFromJsonAsync<JsonElement>();
        var ticketPath = new Uri(issued.GetProperty("uploadUrl").GetString()!).AbsolutePath;
        await host.SetAllowAgentUploadsAsync(false);

        foreach (var response in new HttpResponseMessage[]
        {
            await host.SendAsync(HttpMethod.Get, Api(host), null),
            await host.PostAnonymousAsync(Api(host, "/uploads"), new { fileName = "a.txt", text = "a" }),
            await host.PostAnonymousAsync(Api(host, "/upload-urls"), new { fileName = "a.txt", sizeBytes = 1 }),
            await host.PostAnonymousAsync(Api(host, "/send"), new { files = new[] { new { fileName = "a.txt", text = "a" } }, senderName = "A", senderEmail = "a@example.com" }),
            await host.PutAsync(ticketPath, [1, 2, 3])
        })
        {
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal(DisabledText(host.UploadCode), await ErrorAsync(response));
        }

        Assert.Equal(0, host.StagedPayloadCount());
    }

    [Fact]
    public async Task Posts_need_a_json_content_type()
    {
        await using var host = await Host.StartAsync();

        foreach (var suffix in new[] { "/uploads", "/upload-urls", "/send" })
        {
            var response = await host.SendAsync(HttpMethod.Post, Api(host, suffix), null, new StringContent("{}", Encoding.UTF8, "text/plain"));
            Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        }
    }

    [Fact]
    public async Task Drafts_are_minted_by_the_server_and_a_client_chosen_id_is_refused()
    {
        await using var host = await Host.StartAsync();

        var chosen = await host.PostAnonymousAsync(Api(host, "/uploads"), new { draftId = "0123456789abcdef0123456789abcdef", fileName = "a.txt", text = "a" });
        Assert.Equal(HttpStatusCode.BadRequest, chosen.StatusCode);
        Assert.StartsWith("Unknown draftId", await ErrorAsync(chosen));
        foreach (var bad in new[] { "../../x", "example", "draft1" })
        {
            Assert.Equal(HttpStatusCode.BadRequest, (await host.PostAnonymousAsync(Api(host, "/uploads"), new { draftId = bad, fileName = "a.txt", text = "a" })).StatusCode);
        }

        var first = await host.PostAnonymousAsync(Api(host, "/uploads"), new { fileName = "a.txt", text = "a" });
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        var draftId = (await first.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("draftId").GetString()!;
        Assert.Equal(32, draftId.Length);

        var second = await host.PostAnonymousAsync(Api(host, "/uploads"), new { draftId, fileName = "b.txt", text = "b" });
        Assert.Equal(HttpStatusCode.Created, second.StatusCode);
        Assert.Equal(draftId, (await second.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("draftId").GetString());

        // A draft issued for the old code is not valid for the regenerated one.
        await host.RegenerateCodeAsync("linkcode2");
        var stale = await host.PostAnonymousAsync(Api(host, "/uploads"), new { draftId, fileName = "c.txt", text = "c" });
        Assert.Equal(HttpStatusCode.BadRequest, stale.StatusCode);
    }

    [Fact]
    public async Task Send_after_an_upload_url_creates_a_received_share_marked_as_sent_by_the_agent()
    {
        await using var host = await Host.StartAsync();
        var issued = await (await host.PostAnonymousAsync(Api(host, "/upload-urls"), new { fileName = "report.pdf", sizeBytes = 4 })).Content.ReadFromJsonAsync<JsonElement>();
        var draftId = issued.GetProperty("draftId").GetString()!;
        Assert.Equal(HttpStatusCode.Created, (await host.PutAsync(new Uri(issued.GetProperty("uploadUrl").GetString()!).AbsolutePath, [1, 2, 3, 4])).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await host.PutAsync(new Uri(issued.GetProperty("uploadUrl").GetString()!).AbsolutePath, [1, 2, 3, 4])).StatusCode);

        var send = await host.PostAnonymousAsync(Api(host, "/send"), new { draftId, senderName = "Report Bot", senderEmail = "BOT@example.com", message = "Weekly report" });

        Assert.Equal(HttpStatusCode.Accepted, send.StatusCode);
        var body = await send.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("queued", body.GetProperty("state").GetString());
        Assert.False(body.TryGetProperty("token", out _));
        var payload = await host.RunLastJobAsync();
        Assert.True(payload.SentByAgent);
        var share = Assert.Single(await host.SharesAsync());
        Assert.True(share.SentByAgent);
        Assert.Equal("Report Bot", share.SenderName);
        Assert.Equal("bot@example.com", share.SenderEmail);
        Assert.Equal("Weekly report", share.SenderMessage);
        Assert.Null(share.CreatedByApiTokenId);

        // Sending the same draft again is the browser's "already submitted".
        var again = await host.PostAnonymousAsync(Api(host, "/send"), new { draftId, senderName = "Report Bot", senderEmail = "bot@example.com" });
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
    }

    [Fact]
    public async Task Send_with_inline_files_stages_and_submits_in_one_call()
    {
        await using var host = await Host.StartAsync();

        var send = await host.PostAnonymousAsync(Api(host, "/send"), new
        {
            files = new object[] { new { fileName = "a.txt", text = "alpha" }, new { fileName = "b.bin", contentBase64 = Convert.ToBase64String(new byte[] { 1, 2, 3 }) } },
            senderName = "Report Bot",
            senderEmail = "bot@example.com"
        });

        Assert.Equal(HttpStatusCode.Accepted, send.StatusCode);
        var payload = await host.RunLastJobAsync();
        Assert.Equal(2, payload.UploadedFileIds.Count);
        Assert.Equal(2, (await host.ShareFilesAsync(Assert.Single(await host.SharesAsync()).ShareToken)).Count);
    }

    [Theory]
    [InlineData("", "bot@example.com", "senderName is required.")]
    [InlineData("Bot", "not-an-email", "senderEmail must be a valid email address.")]
    [InlineData("Bot", "", "senderEmail must be a valid email address.")]
    public async Task Sender_fields_are_validated_like_the_browser_form_and_nothing_is_staged(string name, string email, string expected)
    {
        await using var host = await Host.StartAsync();

        var response = await host.PostAnonymousAsync(Api(host, "/send"),
            new { files = new[] { new { fileName = "a.txt", text = "a" } }, senderName = name, senderEmail = email });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(expected, await ErrorAsync(response));
        Assert.Equal(0, host.StagedPayloadCount());
    }

    [Fact]
    public async Task Send_needs_files_or_a_draft_and_an_unknown_draft_is_refused()
    {
        await using var host = await Host.StartAsync();

        Assert.Equal("draftId or files is required.", await ErrorAsync(await host.PostAnonymousAsync(Api(host, "/send"), Sender)));
        var chosen = await host.PostAnonymousAsync(Api(host, "/send"), new { draftId = "0123456789abcdef0123456789abcdef", senderName = "A", senderEmail = "a@example.com" });
        Assert.Equal(HttpStatusCode.BadRequest, chosen.StatusCode);
        Assert.StartsWith("Unknown draftId", await ErrorAsync(chosen));
    }

    [Fact]
    public async Task Regenerating_the_code_ends_the_old_code_and_its_tickets()
    {
        await using var host = await Host.StartAsync();
        var oldCode = host.UploadCode;
        var issued = await (await host.PostAnonymousAsync(Api(host, "/upload-urls"), new { fileName = "a.txt", sizeBytes = 3 })).Content.ReadFromJsonAsync<JsonElement>();
        var ticketPath = new Uri(issued.GetProperty("uploadUrl").GetString()!).AbsolutePath;

        await host.RegenerateCodeAsync("linkcode2");

        Assert.Equal(HttpStatusCode.NotFound, (await host.PutAsync(ticketPath, [1, 2, 3])).StatusCode);
        var oldRoute = await host.SendAsync(HttpMethod.Get, $"/api/v1/upload-links/{oldCode}", null);
        Assert.Equal(HttpStatusCode.NotFound, oldRoute.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, Api(host), null)).StatusCode);
    }

    [Fact]
    public async Task Open_draft_caps_apply_per_address_and_per_code()
    {
        await using (var perIp = await Host.StartAsync(o => o.PublicUploads.MaxOpenDraftsPerIp = 1))
        {
            Assert.Equal(HttpStatusCode.Created, (await perIp.PostAnonymousAsync(Api(perIp, "/uploads"), new { fileName = "a.txt", text = "a" })).StatusCode);
            var refused = await perIp.PostAnonymousAsync(Api(perIp, "/uploads"), new { fileName = "b.txt", text = "b" });
            Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
            Assert.Contains("from your network", await ErrorAsync(refused));
        }

        await using var perCode = await Host.StartAsync(o => o.PublicUploads.MaxOpenDraftsPerToken = 1);
        Assert.Equal(HttpStatusCode.Created, (await perCode.PostAnonymousAsync(Api(perCode, "/upload-urls"), new { fileName = "a.txt", sizeBytes = 1 })).StatusCode);
        var second = await perCode.PostAnonymousAsync(Api(perCode, "/upload-urls"), new { fileName = "b.txt", sizeBytes = 1 });
        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
        Assert.Contains("too many uploads in progress", await ErrorAsync(second));
    }

    [Fact]
    public async Task The_public_stage_budget_of_the_link_refuses_with_413()
    {
        await using var host = await Host.StartAsync(o => o.PublicUploads.MaxOpenDraftBytesPerToken = 5);

        var response = await host.PostAnonymousAsync(Api(host, "/uploads"), new { fileName = "a.txt", text = "0123456789" });

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task The_daily_quota_of_received_shares_refuses_with_429()
    {
        await using var host = await Host.StartAsync(o => o.PublicUploads.MaxSharesPerCodePerDay = 1);
        var body = new { files = new[] { new { fileName = "a.txt", text = "a" } }, senderName = "Bot", senderEmail = "bot@example.com" };
        Assert.Equal(HttpStatusCode.Accepted, (await host.PostAnonymousAsync(Api(host, "/send"), body)).StatusCode);
        await host.RunLastJobAsync();

        var second = await host.PostAnonymousAsync(Api(host, "/send"), body);

        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
        Assert.Contains("daily limit", await ErrorAsync(second));
    }

    [Fact]
    public async Task Agent_and_browser_requests_share_the_public_upload_bucket_and_the_26th_is_429_with_retry_after()
    {
        await using var host = await Host.StartAsync(rateLimited: true);

        for (var i = 0; i < 20; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, "/test/browser-upload", null)).StatusCode);
        }

        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, Api(host), null)).StatusCode);
        }

        var limited = await host.SendAsync(HttpMethod.Get, Api(host), null);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.True(limited.Headers.Contains("Retry-After"));
        Assert.Equal(HttpStatusCode.TooManyRequests, (await host.SendAsync(HttpMethod.Get, "/test/browser-upload", null)).StatusCode);
    }

    [Fact]
    public async Task Owner_tickets_stop_working_when_their_token_is_revoked()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueAgentTokenAsync("all");
        var uploadPath = await host.IssueUrlAsync(token, "a.txt", 3);
        var created = await host.CreateShareAndRunJobAsync(token, new { files = new[] { new { fileName = "a.txt", text = "payload" } }, expiry = "indefinite", notify = "none", waitSeconds = 10 });
        var shareToken = (await created.Response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!;
        var downloadPath = await host.IssueDownloadUrlAsync(token, shareToken, (await host.ShareFilesAsync(shareToken)).Single().Id);

        await host.RevokeAsync(token);

        Assert.Equal(HttpStatusCode.NotFound, (await host.PutAsync(uploadPath, [1, 2, 3])).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await host.SendAsync(HttpMethod.Get, downloadPath, null)).StatusCode);
    }

    [Fact]
    public async Task Owner_tickets_stop_working_when_the_account_is_disabled()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueAgentTokenAsync("own");
        var uploadPath = await host.IssueUrlAsync(token, "a.txt", 3);

        await host.DisableOwnerAsync();

        Assert.Equal(HttpStatusCode.NotFound, (await host.PutAsync(uploadPath, [1, 2, 3])).StatusCode);
    }
}
