using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Hangfire;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Web.Auth;
using Agora.Web.Endpoints;
using Agora.Web.Pages.Connect;
using Agora.Web.Services;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Agora.Application.Tests;

/// <summary>
/// The OAuth surface of the agent interface over a TestServer with the real authentication wiring, the consent page and
/// the <c>/api/v1</c> endpoints: discovery documents, dynamic client registration, authorize and approve, and the
/// JSON and form code exchange.
/// </summary>
public sealed class OAuthHostTests
{
    private const string Base = "https://files.example.test";
    private const string Loopback = "http://127.0.0.1:53111/callback";
    private const string State = "state-123";

    [Fact]
    public async Task Metadata_documents_use_the_public_base_url_and_are_no_store_without_cookies()
    {
        await using var host = await Host.StartAsync();

        var resource = await host.GetAsync("/.well-known/oauth-protected-resource/mcp");
        var server = await host.GetAsync("/.well-known/oauth-authorization-server");

        foreach (var response in new[] { resource, server })
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
            Assert.False(response.Headers.Contains("Set-Cookie"));
        }

        var prm = await resource.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal($"{Base}/mcp", prm.GetProperty("resource").GetString());
        Assert.Equal([Base], prm.GetProperty("authorization_servers").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(["header"], prm.GetProperty("bearer_methods_supported").EnumerateArray().Select(x => x.GetString()));

        var meta = await server.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(Base, meta.GetProperty("issuer").GetString());
        Assert.Equal($"{Base}/connect/authorize", meta.GetProperty("authorization_endpoint").GetString());
        Assert.Equal($"{Base}/api/v1/auth/token", meta.GetProperty("token_endpoint").GetString());
        Assert.Equal($"{Base}/oauth/register", meta.GetProperty("registration_endpoint").GetString());
        Assert.Equal(["S256"], meta.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(["none"], meta.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(["authorization_code"], meta.GetProperty("grant_types_supported").EnumerateArray().Select(x => x.GetString()));
    }

    [Fact]
    public async Task There_is_no_root_protected_resource_document()
    {
        await using var host = await Host.StartAsync();

        Assert.Equal(HttpStatusCode.NotFound, (await host.GetAsync("/.well-known/oauth-protected-resource")).StatusCode);
    }

    [Fact]
    public async Task Registration_returns_a_stateless_client_and_sanitizes_the_name()
    {
        await using var host = await Host.StartAsync();

        var response = await host.RegisterAsync(new { redirect_uris = new[] { Loopback }, client_name = "  Claude\u0000 Code ", token_endpoint_auth_method = "client_secret_basic", grant_types = new[] { "authorization_code", "refresh_token" } });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
        Assert.False(response.Headers.Contains("Set-Cookie"));
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.StartsWith("agora_mcp_", body.GetProperty("client_id").GetString());
        Assert.Equal("Claude Code", body.GetProperty("client_name").GetString());
        Assert.Equal([Loopback], body.GetProperty("redirect_uris").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal("none", body.GetProperty("token_endpoint_auth_method").GetString());
        Assert.Equal(["authorization_code"], body.GetProperty("grant_types").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(["code"], body.GetProperty("response_types").EnumerateArray().Select(x => x.GetString()));
        Assert.True(body.TryGetProperty("client_id_issued_at", out _));
        Assert.Equal(0, await host.CountAsync(db => db.ApiTokens.CountAsync()));
    }

    [Theory]
    [InlineData("""{"client_name":"x"}""")]
    [InlineData("""{"redirect_uris":[]}""")]
    [InlineData("""{"redirect_uris":["http://127.0.0.1:1/a","http://127.0.0.1:1/b","http://127.0.0.1:1/c","http://127.0.0.1:1/d","http://127.0.0.1:1/e","http://127.0.0.1:1/f"]}""")]
    [InlineData("""{"redirect_uris":["https://evil.example/cb"]}""")]
    [InlineData("""{"redirect_uris":["http://127.0.0.1:5/cb?x=1"]}""")]
    [InlineData("""{"redirect_uris":["https://claude.ai/cb","javascript:alert(1)"]}""")]
    [InlineData("""{"redirect_uris":[1]}""")]
    [InlineData("not json")]
    public async Task Registration_refuses_invalid_bodies(string json)
    {
        await using var host = await Host.StartAsync();

        var response = await host.PostRawAsync("/oauth/register", json, "application/json");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.StartsWith("invalid_", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Registration_refuses_a_long_client_name_and_non_json()
    {
        await using var host = await Host.StartAsync();

        Assert.Equal(HttpStatusCode.BadRequest, (await host.RegisterAsync(new { redirect_uris = new[] { Loopback }, client_name = new string('a', 201) })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await host.PostRawAsync("/oauth/register", "redirect_uris=x", "application/x-www-form-urlencoded")).StatusCode);
    }

    [Fact]
    public async Task Registration_body_is_limited_to_16_KiB()
    {
        await using var host = await Host.StartAsync();
        var json = JsonSerializer.Serialize(new { redirect_uris = new[] { Loopback }, client_name = new string('a', 20 * 1024) });

        var response = await host.PostRawAsync("/oauth/register", json, "application/json");

        Assert.True(response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.RequestEntityTooLarge, response.StatusCode.ToString());
    }

    [Fact]
    public async Task Registration_is_rate_limited_per_address()
    {
        await using var host = await Host.StartAsync(limitAuthEndpoints: true);
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 12; i++)
        {
            statuses.Add((await host.RegisterAsync(new { redirect_uris = new[] { Loopback } })).StatusCode);
        }

        Assert.Equal(10, statuses.Count(x => x == HttpStatusCode.Created));
        Assert.Equal(2, statuses.Count(x => x == HttpStatusCode.TooManyRequests));
    }

    [Fact]
    public async Task Https_host_outside_the_trust_list_is_refused_and_a_configured_one_is_accepted()
    {
        await using var plain = await Host.StartAsync();
        await using var trusting = await Host.StartAsync(allowedHosts: "agents.example.org");
        var body = new { redirect_uris = new[] { "https://agents.example.org/cb" } };

        Assert.Equal(HttpStatusCode.BadRequest, (await plain.RegisterAsync(body)).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await trusting.RegisterAsync(body)).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await plain.RegisterAsync(new { redirect_uris = new[] { "https://claude.ai/api/mcp/auth_callback" } })).StatusCode);
    }

    [Fact]
    public async Task Full_flow_registers_approves_all_exchanges_by_form_and_reports_the_level_on_me()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        var clientId = await host.RegisterClientAsync("Claude Code", Loopback);
        var pkce = Pkce.New();

        // The registered port is ignored for loopback: the client uses another one at authorize time.
        const string redirect = "http://127.0.0.1:60999/callback";
        var page = await host.GetPageAsync(host.AuthorizeUrl(clientId, redirect, pkce, resource: $"{Base}/mcp"));

        Assert.Equal(HttpStatusCode.OK, page.Status);
        Assert.Contains("no-store", page.Headers["Cache-Control"]);
        Assert.Contains("Allow <span class=\"font-medium text-ink break-words\" data-connect-device>Claude Code</span> to use your Agora account?", page.Body);
        Assert.Contains("The name is chosen by the app and is not verified.", page.Body);
        Assert.Contains("127.0.0.1:60999", page.Body);
        Assert.Matches("<input type=\"radio\" name=\"accessLevel\" value=\"own\" checked", page.Body);
        Assert.DoesNotMatch("value=\"all\" checked", page.Body);
        Assert.Contains("Only shares it creates", page.Body);
        Assert.Contains("All my shares", page.Body);
        Assert.Contains($"name=\"resource\" value=\"{Base}/mcp\"", page.Body);

        var approved = await host.PostPageAsync(page, new() { ["accessLevel"] = "all", ["decision"] = "approve" });

        Assert.Equal(HttpStatusCode.Redirect, approved.Status);
        var location = new Uri(approved.Headers["Location"]);
        Assert.StartsWith("http://127.0.0.1:60999/callback?", location.OriginalString, StringComparison.Ordinal);
        var query = HttpUtility.ParseQueryString(location.Query);
        Assert.Equal(State, query["state"]);

        var exchange = await host.PostFormAsync("/api/v1/auth/token", new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = query["code"]!,
            ["code_verifier"] = pkce.Verifier,
            ["client_id"] = clientId,
            ["resource"] = $"{Base}/mcp"
        });

        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
        Assert.Equal("no-store", exchange.Headers.CacheControl!.ToString());
        var token = (await exchange.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("access_token").GetString()!;
        var me = await host.GetAsync("/api/v1/me", token);
        Assert.Equal("all", (await me.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessLevel").GetString());
        var row = await host.QueryAsync(db => db.ApiTokens.AsNoTracking().SingleAsync());
        Assert.Equal(OAuthClients.StoredClientId(clientId), row.ClientId);
        Assert.Equal("Claude Code", row.DeviceName);
        Assert.Equal("all", row.AccessLevel);
        Assert.Equal(redirect, row.RedirectUri);
    }

    [Fact]
    public async Task Approving_without_a_choice_gives_own_and_an_invalid_choice_falls_back_to_own()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        var clientId = await host.RegisterClientAsync("Agent", Loopback);

        foreach (var choice in new string?[] { null, "capture", "root" })
        {
            var pkce = Pkce.New();
            var page = await host.GetPageAsync(host.AuthorizeUrl(clientId, Loopback, pkce));
            var fields = new Dictionary<string, string> { ["decision"] = "approve" };
            if (choice is not null)
            {
                fields["accessLevel"] = choice;
            }

            var approved = await host.PostPageAsync(page, fields);
            var code = HttpUtility.ParseQueryString(new Uri(approved.Headers["Location"]).Query)["code"]!;
            var result = await host.PostJsonAsync("/api/v1/auth/token", new { grant_type = "authorization_code", code, code_verifier = pkce.Verifier, redirect_uri = Loopback, client_id = clientId });
            var token = (await result.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("access_token").GetString()!;
            Assert.Equal("own", (await (await host.GetAsync("/api/v1/me", token)).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessLevel").GetString());
        }
    }

    [Fact]
    public async Task Deny_redirects_with_access_denied_and_creates_nothing()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        var clientId = await host.RegisterClientAsync("Agent", Loopback);
        var page = await host.GetPageAsync(host.AuthorizeUrl(clientId, Loopback, Pkce.New()));

        var denied = await host.PostPageAsync(page, new() { ["decision"] = "deny", ["accessLevel"] = "all" });

        Assert.Equal(HttpStatusCode.Redirect, denied.Status);
        Assert.Equal($"{Loopback}?error=access_denied&state={State}", denied.Headers["Location"]);
        Assert.Equal(0, await host.CountAsync(db => db.ApiTokens.CountAsync()));
    }

    [Fact]
    public async Task Https_client_can_use_its_registered_redirect_and_the_consent_page_names_the_host()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        const string redirect = "https://claude.ai/api/mcp/auth_callback";
        var clientId = await host.RegisterClientAsync("Claude", redirect);
        var pkce = Pkce.New();

        var page = await host.GetPageAsync(host.AuthorizeUrl(clientId, redirect, pkce));
        var approved = await host.PostPageAsync(page, new() { ["decision"] = "approve" });

        Assert.Contains("data-connect-redirect-host>claude.ai<", page.Body);
        Assert.StartsWith(redirect + "?code=", approved.Headers["Location"], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://127.0.0.1:5/other")]
    [InlineData("http://localhost:5/callback")]
    [InlineData("https://claude.ai/cb")]
    [InlineData("https://evil.example/cb")]
    public async Task Unregistered_redirect_shows_the_error_page_and_never_redirects(string redirect)
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        var clientId = await host.RegisterClientAsync("Agent", Loopback);

        var page = await host.GetPageAsync(host.AuthorizeUrl(clientId, redirect, Pkce.New()));

        Assert.Equal(HttpStatusCode.BadRequest, page.Status);
        Assert.False(page.Headers.ContainsKey("Location"));
        Assert.Contains("data-connect-error", page.Body);
    }

    [Fact]
    public async Task Tampered_or_foreign_client_id_shows_the_error_page()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        var clientId = await host.RegisterClientAsync("Agent", Loopback);

        foreach (var bad in new[] { clientId[..^3] + "AAA", "agora_mcp_garbage", "agora_mcp_" })
        {
            var page = await host.GetPageAsync(host.AuthorizeUrl(bad, Loopback, Pkce.New()));
            Assert.Equal(HttpStatusCode.BadRequest, page.Status);
            Assert.Contains("data-connect-error", page.Body);
            Assert.False(page.Headers.ContainsKey("Location"));
        }
    }

    [Fact]
    public async Task Mismatched_resource_redirects_with_invalid_target()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        var clientId = await host.RegisterClientAsync("Agent", Loopback);

        var page = await host.GetPageAsync(host.AuthorizeUrl(clientId, Loopback, Pkce.New(), resource: "https://other.example/mcp"));

        Assert.Equal(HttpStatusCode.Redirect, page.Status);
        Assert.Equal($"{Loopback}?error=invalid_target&state={State}", page.Headers["Location"]);
    }

    [Fact]
    public async Task Missing_state_or_plain_pkce_redirects_with_invalid_request()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        var clientId = await host.RegisterClientAsync("Agent", Loopback);
        var pkce = Pkce.New();

        var noState = await host.GetPageAsync(host.AuthorizeUrl(clientId, Loopback, pkce).Replace($"&state={State}", string.Empty));
        var plain = await host.GetPageAsync(host.AuthorizeUrl(clientId, Loopback, pkce).Replace("code_challenge_method=S256", "code_challenge_method=plain"));

        Assert.Equal(HttpStatusCode.Redirect, noState.Status);
        Assert.Equal($"{Loopback}?error=invalid_request", noState.Headers["Location"]);
        Assert.Equal(HttpStatusCode.Redirect, plain.Status);
        Assert.StartsWith($"{Loopback}?error=invalid_request", plain.Headers["Location"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Resource_mismatch_at_the_token_endpoint_is_invalid_target_and_keeps_the_code_usable()
    {
        await using var host = await Host.StartAsync();
        var (clientId, code, pkce) = await host.ApproveAsync("Agent", "own");

        var wrong = await host.PostFormAsync("/api/v1/auth/token", host.TokenForm(clientId, code, pkce, resource: "https://other.example/mcp"));
        var ok = await host.PostFormAsync("/api/v1/auth/token", host.TokenForm(clientId, code, pkce, resource: $"{Base.ToUpperInvariant()}/mcp/"));

        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        Assert.Equal("invalid_target", (await wrong.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    [Fact]
    public async Task Exchange_accepts_json_and_a_matching_or_omitted_redirect_for_registered_clients()
    {
        await using var host = await Host.StartAsync();
        var first = await host.ApproveAsync("Agent", "own");
        var second = await host.ApproveAsync("Agent", "own");

        var json = await host.PostJsonAsync("/api/v1/auth/token", new { grant_type = "authorization_code", code = first.Code, code_verifier = first.Pkce.Verifier, redirect_uri = Loopback, client_id = first.ClientId });
        var omitted = await host.PostFormAsync("/api/v1/auth/token", host.TokenForm(second.ClientId, second.Code, second.Pkce));

        Assert.Equal(HttpStatusCode.OK, json.StatusCode);
        Assert.Equal(HttpStatusCode.OK, omitted.StatusCode);
    }

    [Fact]
    public async Task Exchange_with_a_different_redirect_or_verifier_or_replayed_code_is_invalid_grant()
    {
        await using var host = await Host.StartAsync();
        var a = await host.ApproveAsync("Agent", "own");
        var b = await host.ApproveAsync("Agent", "own");
        var c = await host.ApproveAsync("Agent", "own");

        var otherRedirect = await host.PostFormAsync("/api/v1/auth/token", host.TokenForm(a.ClientId, a.Code, a.Pkce, redirect: "http://127.0.0.1:5/callback"));
        var wrongVerifier = await host.PostFormAsync("/api/v1/auth/token", host.TokenForm(b.ClientId, b.Code, Pkce.New()));
        Assert.Equal(HttpStatusCode.OK, (await host.PostFormAsync("/api/v1/auth/token", host.TokenForm(c.ClientId, c.Code, c.Pkce))).StatusCode);
        var replay = await host.PostFormAsync("/api/v1/auth/token", host.TokenForm(c.ClientId, c.Code, c.Pkce));

        foreach (var response in new[] { otherRedirect, wrongVerifier, replay })
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("invalid_grant", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        }
    }

    [Fact]
    public async Task Code_cannot_be_exchanged_by_another_client()
    {
        await using var host = await Host.StartAsync();
        var a = await host.ApproveAsync("Agent", "own");
        var other = await host.RegisterClientAsync("Other", Loopback);

        var response = await host.PostFormAsync("/api/v1/auth/token", host.TokenForm(other, a.Code, a.Pkce));

        Assert.Equal("invalid_grant", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
    }

    [Theory]
    [InlineData("agora_mcp_garbage")]
    [InlineData("agora_mcp_")]
    public async Task Undecodable_client_id_gets_invalid_client(string clientId)
    {
        await using var host = await Host.StartAsync();

        var response = await host.PostFormAsync("/api/v1/auth/token", new()
        {
            ["grant_type"] = "authorization_code", ["code"] = "x", ["code_verifier"] = Pkce.New().Verifier, ["client_id"] = clientId
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_client", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Capture_json_exchange_is_unchanged_and_form_exchange_works_for_the_capture_client()
    {
        await using var host = await Host.StartAsync();
        var jsonCode = await host.CaptureCodeAsync();
        var formCode = await host.CaptureCodeAsync();
        const string redirect = ApiTokenServiceTests.Redirect;

        var json = await host.PostJsonAsync("/api/v1/auth/token", new { grant_type = "authorization_code", code = jsonCode, code_verifier = ApiTokenServiceTests.Verifier, redirect_uri = redirect, client_id = "agora-capture" });
        var form = await host.PostFormAsync("/api/v1/auth/token", new()
        {
            ["grant_type"] = "authorization_code", ["code"] = formCode, ["code_verifier"] = ApiTokenServiceTests.Verifier, ["redirect_uri"] = redirect, ["client_id"] = "agora-capture"
        });

        foreach (var response in new[] { json, form })
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(["access_token", "email", "token_id", "token_type"], body.EnumerateObject().Select(x => x.Name).Order(StringComparer.Ordinal));
            var me = await host.GetAsync("/api/v1/me", body.GetProperty("access_token").GetString());
            Assert.Equal("capture", (await me.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessLevel").GetString());
        }

        Assert.All(await host.QueryAsync(db => db.ApiTokens.AsNoTracking().ToListAsync()), x => Assert.Null(x.AccessLevel));
    }

    [Fact]
    public async Task Capture_exchange_error_shapes_are_unchanged()
    {
        await using var host = await Host.StartAsync();

        var plain = await host.PostRawAsync("/api/v1/auth/token", "x", "text/plain");
        var noRedirect = await host.PostJsonAsync("/api/v1/auth/token", new { grant_type = "authorization_code", code = "c", code_verifier = "v", client_id = "agora-capture" });
        var unknown = await host.PostJsonAsync("/api/v1/auth/token", new { grant_type = "authorization_code", code = "c", code_verifier = "v", redirect_uri = "r", client_id = "other" });
        var grant = await host.PostJsonAsync("/api/v1/auth/token", new { grant_type = "password", code = "c" });

        await AssertErrorAsync(plain, "invalid_request", "Send the request as application/json.");
        await AssertErrorAsync(noRedirect, "invalid_request", "code, code_verifier, redirect_uri and client_id are required.");
        await AssertErrorAsync(unknown, "invalid_request", "Unknown client_id.");
        await AssertErrorAsync(grant, "unsupported_grant_type", "Only authorization_code is supported.");
        Assert.Equal("no-store", plain.Headers.CacheControl!.ToString());
        Assert.Equal("no-cache", plain.Headers.Pragma.ToString());
    }

    [Fact]
    public async Task Capture_consent_page_keeps_its_markup()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        var url = $"/connect/authorize?client_id=agora-capture&redirect_uri={Uri.EscapeDataString(ApiTokenServiceTests.Redirect)}&state={State}" +
                  $"&code_challenge={ApiTokenServiceTests.Challenge}&code_challenge_method=S256&device_name=My%20Mac";

        var page = await host.GetPageAsync(url);

        Assert.Equal(HttpStatusCode.OK, page.Status);
        Assert.Contains("to create temporary links in your account?", page.Body);
        Assert.Contains("create temporary direct links from images it uploads", page.Body);
        Assert.Contains("name=\"device_name\" value=\"My Mac\"", page.Body);
        Assert.DoesNotContain("accessLevel", page.Body);
        Assert.DoesNotContain("not verified", page.Body);

        var approved = await host.PostPageAsync(page, new() { ["decision"] = "approve" });
        Assert.StartsWith($"{ApiTokenServiceTests.Redirect}?code=", approved.Headers["Location"], StringComparison.Ordinal);
        Assert.Null((await host.QueryAsync(db => db.ApiTokens.AsNoTracking().SingleAsync())).AccessLevel);
    }

    [Fact]
    public async Task Capture_client_with_an_unregistered_style_redirect_is_still_refused()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();

        var page = await host.GetPageAsync($"/connect/authorize?client_id=agora-capture&redirect_uri={Uri.EscapeDataString("https://claude.ai/cb")}&state={State}&code_challenge={ApiTokenServiceTests.Challenge}&code_challenge_method=S256");

        Assert.Equal(HttpStatusCode.BadRequest, page.Status);
        Assert.Contains("data-connect-error", page.Body);
    }

    [Theory]
    [InlineData("&response_type=token")]
    [InlineData("&response_type=")]
    [InlineData("&response_type=code&response_type=code")]
    [InlineData("")]
    public async Task Mcp_authorize_requires_response_type_code_and_shows_the_error_page(string responseType)
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        var clientId = await host.RegisterClientAsync("Claude", "https://claude.ai/api/mcp/auth_callback");
        var url = host.AuthorizeUrl(clientId, "https://claude.ai/api/mcp/auth_callback", Pkce.New()).Replace("response_type=code", "x=1") + responseType;

        var page = await host.GetPageAsync(url);

        Assert.Equal(HttpStatusCode.BadRequest, page.Status);
        Assert.Contains("data-connect-error", page.Body);
    }

    [Fact]
    public async Task Capture_authorize_without_response_type_still_works_but_a_wrong_one_is_refused()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        var url = $"/connect/authorize?client_id=agora-capture&redirect_uri={Uri.EscapeDataString(ApiTokenServiceTests.Redirect)}&state={State}" +
                  $"&code_challenge={ApiTokenServiceTests.Challenge}&code_challenge_method=S256&device_name=My%20Mac";

        var without = await host.GetPageAsync(url);
        var code = await host.GetPageAsync(url + "&response_type=code");
        var token = await host.GetPageAsync(url + "&response_type=token");

        Assert.Equal(HttpStatusCode.OK, without.Status);
        Assert.Equal(HttpStatusCode.OK, code.Status);
        Assert.Equal(HttpStatusCode.BadRequest, token.Status);
    }

    [Fact]
    public async Task Machine_routes_ignore_the_session_cookie_and_never_set_cookies()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        await host.QueryAsync(async db =>
        {
            var user = await db.Users.SingleAsync();
            user.AllowAgentUploads = true;
            return await db.SaveChangesAsync();
        });
        var code = await host.QueryAsync(db => db.Users.Select(x => x.UploadToken).SingleAsync());

        var who = await host.GetPageAsync("/test/api-who");
        var llms = await host.GetPageAsync($"/u/{code}/llms.txt");

        Assert.Equal("anonymous", who.Body);
        Assert.False(who.Headers.ContainsKey("Set-Cookie"));
        Assert.Equal(HttpStatusCode.OK, llms.Status);
        Assert.False(llms.Headers.ContainsKey("Set-Cookie"));
    }

    private static async Task AssertErrorAsync(HttpResponseMessage response, string error, string description)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(error, body.GetProperty("error").GetString());
        Assert.Equal(description, body.GetProperty("error_description").GetString());
    }

    private sealed record Pkce(string Verifier, string Challenge)
    {
        public static Pkce New()
        {
            var verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return new Pkce(verifier, challenge);
        }
    }

    private sealed record Reply(HttpStatusCode Status, string Body, Dictionary<string, string> Headers);

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _connection;
        private readonly HttpClient _client;
        private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);
        private string _storageRoot = string.Empty;
        private Guid _userId;
        private string _stamp = string.Empty;

        private Host(WebApplication app, SqliteConnection connection)
        {
            _app = app;
            _connection = connection;
            _client = app.GetTestClient();
        }

        public static async Task<Host> StartAsync(string? allowedHosts = null, bool limitAuthEndpoints = false)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            if (allowedHosts is not null)
            {
                builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Agora:Agents:AllowedRedirectHosts:0"] = allowedHosts });
            }

            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-oauth-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var options = new AgoraOptions { StorageRoot = storageRoot, Scratch = { MaxBytes = 0, MinFreeBytes = 0 } };
            builder.Services.Configure<AgoraOptions>(o =>
            {
                o.StorageRoot = storageRoot;
                o.Scratch = options.Scratch;
            });
            // The /api/v1 endpoints resolve these (the capture and delete handlers); the OAuth flows never use them.
            builder.Services.AddSingleton<UploadConcurrency>();
            builder.Services.AddSingleton<IObjectStore>(new FileSystemObjectStore(storageRoot));
            builder.Services.AddSingleton<IShareContentStore, ShareContentStore>();
            builder.Services.AddSingleton<IBackgroundJobClient>(new NoJobs());
            builder.Services.AddSingleton<KeyedAsyncLock>();
            builder.Services.AddSingleton(new ScratchSpaceMonitor(options, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System));
            builder.Services.AddSingleton<IPublicOriginProvider>(new FixedOrigin());
            builder.Services.AddScoped<ShareManager>();
            builder.Services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
            builder.Services.AddScoped<ApiTokenService>();
            builder.Services.AddSingleton(new PublicBaseUrlResolver(Base, allowRequestHostFallback: false));
            builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
            builder.Services.AddAgoraAuthentication(new AgoraAuthOptions(), CookieSecurePolicy.None);
            builder.Services.AddAuthorization(AuthSetup.ConfigureAuthorization);
            builder.Services.AddRazorPages().AddApplicationPart(typeof(AuthorizeModel).Assembly);
            builder.Services.AddRateLimiter(o => RateLimitSetup.Configure(o, new AgoraRateLimitOptions { AnonymousPerMinute = 0 }, isE2E: !limitAuthEndpoints));
            builder.Services.AddSingleton<Agora.Application.Abstractions.IEmailSender, TestEmailSender>();
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddAgoraAgents();

            var app = builder.Build();
            app.UseAgoraExceptionHandler();
            app.UseAuthentication();
            app.UseRateLimiter();
            app.UseAuthorization();
            app.MapGet("/test/login", async (HttpContext context, AgoraDbContext db) =>
            {
                var user = await db.Users.SingleAsync();
                await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CookieSessions.CreatePrincipal(user));
                return Results.Ok();
            });
            app.MapGet("/test/api-who", (HttpContext context) => Results.Text(context.User.Identity?.IsAuthenticated == true ? "signed-in" : "anonymous"))
                .WithMetadata(Agora.Web.Endpoints.ApiEndpointMetadata.Instance).AllowAnonymous();
            app.MapRazorPages();
            app.MapApiV1Endpoints(captureRequestBodyLimit: 1024 * 1024);
            app.MapAgoraAgents();
            await app.StartAsync();

            var host = new Host(app, connection) { _storageRoot = storageRoot };
            await using var scope = app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            await db.Database.EnsureCreatedAsync();
            var user = TestUsers.Seed(Guid.NewGuid(), "owner@example.com");
            db.Users.Add(user);
            await db.SaveChangesAsync();
            host._userId = user.Id;
            host._stamp = user.SecurityStamp;
            return host;
        }

        public string AuthorizeUrl(string clientId, string redirect, Pkce pkce, string? resource = null) =>
            $"/connect/authorize?response_type=code&client_id={Uri.EscapeDataString(clientId)}&redirect_uri={Uri.EscapeDataString(redirect)}&state={State}" +
            $"&code_challenge={pkce.Challenge}&code_challenge_method=S256" +
            (resource is null ? string.Empty : $"&resource={Uri.EscapeDataString(resource)}");

        public Dictionary<string, string> TokenForm(string clientId, string code, Pkce pkce, string? redirect = null, string? resource = null)
        {
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["code"] = code, ["code_verifier"] = pkce.Verifier, ["client_id"] = clientId
            };
            if (redirect is not null)
            {
                form["redirect_uri"] = redirect;
            }

            if (resource is not null)
            {
                form["resource"] = resource;
            }

            return form;
        }

        public async Task SignInAsync()
        {
            var response = await _client.GetAsync("/test/login");
            foreach (var setCookie in response.Headers.GetValues("Set-Cookie"))
            {
                var pair = setCookie.Split(';')[0].Split('=', 2);
                _cookies[pair[0]] = pair[1];
            }
        }

        public async Task<string> RegisterClientAsync(string name, params string[] redirects)
        {
            var response = await RegisterAsync(new { redirect_uris = redirects, client_name = name });
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("client_id").GetString()!;
        }

        /// <summary>Registers a client, signs in and approves it; returns the authorization code.</summary>
        public async Task<(string ClientId, string Code, Pkce Pkce)> ApproveAsync(string name, string level)
        {
            if (_cookies.Count == 0)
            {
                await SignInAsync();
            }

            var clientId = await RegisterClientAsync(name, Loopback);
            var pkce = Pkce.New();
            var page = await GetPageAsync(AuthorizeUrl(clientId, Loopback, pkce));
            var approved = await PostPageAsync(page, new() { ["decision"] = "approve", ["accessLevel"] = level });
            Assert.Equal(HttpStatusCode.Redirect, approved.Status);
            return (clientId, HttpUtility.ParseQueryString(new Uri(approved.Headers["Location"]).Query)["code"]!, pkce);
        }

        public async Task<string> CaptureCodeAsync()
        {
            await using var scope = _app.Services.CreateAsyncScope();
            return (await scope.ServiceProvider.GetRequiredService<ApiTokenService>()
                .CreatePendingAsync(_userId, _stamp, ApiTokens.CaptureClientId, "Mac", ApiTokenServiceTests.Challenge, ApiTokenServiceTests.Redirect, CancellationToken.None))!;
        }

        public Task<HttpResponseMessage> RegisterAsync(object body) => _client.PostAsJsonAsync("/oauth/register", body);

        public Task<HttpResponseMessage> PostJsonAsync(string path, object body) => _client.PostAsJsonAsync(path, body);

        public Task<HttpResponseMessage> PostFormAsync(string path, Dictionary<string, string> form) =>
            _client.PostAsync(path, new FormUrlEncodedContent(form));

        public Task<HttpResponseMessage> PostRawAsync(string path, string body, string contentType) =>
            _client.PostAsync(path, new StringContent(body, Encoding.UTF8, MediaTypeHeaderValue.Parse(contentType)));

        public async Task<HttpResponseMessage> GetAsync(string path, string? bearer = null)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            if (bearer is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            }

            return await _client.SendAsync(request);
        }

        public async Task<Reply> GetPageAsync(string pathAndQuery)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, pathAndQuery);
            return await SendPageAsync(request);
        }

        /// <summary>Posts the consent form of <paramref name="page"/>: its hidden fields and antiforgery token plus <paramref name="extra"/>.</summary>
        public async Task<Reply> PostPageAsync(Reply page, Dictionary<string, string> extra)
        {
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (Match input in Regex.Matches(page.Body, "<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\""))
            {
                fields[input.Groups[1].Value] = WebUtility.HtmlDecode(input.Groups[2].Value);
            }

            var token = Regex.Match(page.Body, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
            fields["__RequestVerificationToken"] = token;
            foreach (var (key, value) in extra)
            {
                fields[key] = value;
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, "/connect/authorize") { Content = new FormUrlEncodedContent(fields) };
            return await SendPageAsync(request);
        }

        private async Task<Reply> SendPageAsync(HttpRequestMessage request)
        {
            if (_cookies.Count > 0)
            {
                request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(kv => $"{kv.Key}={kv.Value}")));
            }

            var response = await _client.SendAsync(request);
            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var setCookie in cookies)
                {
                    var pair = setCookie.Split(';')[0].Split('=', 2);
                    _cookies[pair[0]] = pair[1];
                }
            }

            var headers = response.Headers.Concat(response.Content.Headers)
                .ToDictionary(h => h.Key, h => string.Join(", ", h.Value), StringComparer.OrdinalIgnoreCase);
            return new Reply(response.StatusCode, await response.Content.ReadAsStringAsync(), headers);
        }

        public async Task<T> QueryAsync<T>(Func<AgoraDbContext, Task<T>> query)
        {
            await using var scope = _app.Services.CreateAsyncScope();
            return await query(scope.ServiceProvider.GetRequiredService<AgoraDbContext>());
        }

        public Task<int> CountAsync(Func<AgoraDbContext, Task<int>> query) => QueryAsync(query);

        public async ValueTask DisposeAsync()
        {
            await _app.DisposeAsync();
            await _connection.DisposeAsync();
            if (Directory.Exists(_storageRoot))
            {
                Directory.Delete(_storageRoot, recursive: true);
            }
        }
    }

    private sealed class NoJobs : IBackgroundJobClient
    {
        public string Create(Hangfire.Common.Job job, Hangfire.States.IState state) => "1";

        public bool ChangeState(string jobId, Hangfire.States.IState state, string expectedState) => true;
    }

    private sealed class FixedOrigin : IPublicOriginProvider
    {
        public string? ConfiguredOrigin => Base;
    }
}
