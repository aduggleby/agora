using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class OAuthClientsTests
{
    [Theory]
    [InlineData("http://127.0.0.1:50123/callback")]
    [InlineData("http://127.0.0.1/cb")]
    [InlineData("http://[::1]:8080/oauth/callback")]
    [InlineData("http://localhost:33418/any/path")]
    [InlineData("http://LOCALHOST:33418/x")]
    [InlineData("https://claude.ai/api/mcp/auth_callback")]
    [InlineData("https://claude.com/api/mcp/auth_callback")]
    [InlineData("https://CLAUDE.AI/cb")]
    public void Allowed_redirects_register(string uri) => Assert.True(OAuthClients.IsAllowedRedirectUri(uri));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("http://example.com/cb")]
    [InlineData("https://example.com/cb")]
    [InlineData("https://claude.ai.evil.example/cb")]
    [InlineData("https://evilclaude.ai/cb")]
    [InlineData("https://user@claude.ai/cb")]
    [InlineData("https://claude.ai/cb#frag")]
    [InlineData("https://claude.ai/cb?x=1")]
    [InlineData("http://127.0.0.1:5000/cb?x=1")]
    [InlineData("http://user@127.0.0.1:5000/cb")]
    [InlineData("http://127.0.0.1.evil.example/cb")]
    [InlineData("https://localhost/cb")]
    [InlineData("https://127.0.0.1/cb")]
    [InlineData("ftp://127.0.0.1/cb")]
    [InlineData("javascript:alert(1)")]
    [InlineData("com.example.app:/cb")]
    [InlineData("/relative")]
    public void Other_redirects_are_refused(string? uri) => Assert.False(OAuthClients.IsAllowedRedirectUri(uri));

    [Fact]
    public void Over_long_redirects_are_refused()
    {
        Assert.False(OAuthClients.IsAllowedRedirectUri("https://claude.ai/" + new string('a', OAuthClients.MaxRedirectUriLength)));
    }

    [Fact]
    public void Https_host_outside_the_built_in_list_needs_the_trust_list()
    {
        Assert.False(OAuthClients.IsAllowedRedirectUri("https://agents.example.org/cb"));
        Assert.True(OAuthClients.IsAllowedRedirectUri("https://agents.example.org/cb", ["agents.example.org"]));
        Assert.True(OAuthClients.IsAllowedRedirectUri("https://Agents.Example.org/cb", ["agents.example.org"]));
        Assert.False(OAuthClients.IsAllowedRedirectUri("https://other.example.org/cb", ["agents.example.org"]));
    }

    [Theory]
    [InlineData("http://127.0.0.1:50000/callback", "http://127.0.0.1:61234/callback", true)]
    [InlineData("http://127.0.0.1/callback", "http://127.0.0.1:61234/callback", true)]
    [InlineData("http://localhost:1/cb", "http://localhost:2/cb", true)]
    [InlineData("http://[::1]:1/cb", "http://[::1]:9999/cb", true)]
    [InlineData("http://127.0.0.1:1/cb", "http://127.0.0.1:2/other", false)]
    [InlineData("http://127.0.0.1:1/cb", "http://localhost:1/cb", false)]
    [InlineData("http://127.0.0.1:1/cb", "http://[::1]:1/cb", false)]
    [InlineData("https://claude.ai/cb", "https://claude.ai/cb", true)]
    [InlineData("https://claude.ai/cb", "https://claude.ai/cb2", false)]
    [InlineData("https://claude.ai/cb", "https://claude.com/cb", false)]
    [InlineData("https://claude.ai/cb", "https://claude.ai:8443/cb", false)]
    [InlineData("http://127.0.0.1:1/cb", "https://claude.ai/cb", false)]
    public void Redirect_matching_ignores_only_the_loopback_port(string registered, string requested, bool expected) =>
        Assert.Equal(expected, OAuthClients.MatchesRegistered([registered], requested));

    [Fact]
    public void A_requested_redirect_must_itself_be_allowed_even_when_registered()
    {
        Assert.False(OAuthClients.MatchesRegistered(["https://evil.example/cb"], "https://evil.example/cb"));
    }

    [Theory]
    [InlineData("https://files.example.test/mcp", true)]
    [InlineData("https://files.example.test/mcp/", true)]
    [InlineData("https://FILES.example.test/mcp", true)]
    [InlineData("HTTPS://files.example.test", true)]
    [InlineData("https://files.example.test/", true)]
    [InlineData("https://files.example.test:443/mcp", true)]
    [InlineData("https://files.example.test/other", false)]
    [InlineData("https://files.example.test/mcp//", false)]
    [InlineData("https://files.example.test/mcp?x=1", false)]
    [InlineData("http://files.example.test/mcp", false)]
    [InlineData("https://evil.example/mcp", false)]
    [InlineData("https://files.example.test:8443/mcp", false)]
    [InlineData("https://user@files.example.test/mcp", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Resource_must_name_this_server(string? resource, bool expected) =>
        Assert.Equal(expected, OAuthClients.IsValidResource(resource, "https://files.example.test"));

    [Fact]
    public void Stored_client_id_is_prefixed_and_a_stable_32_hex_hash()
    {
        var stored = OAuthClients.StoredClientId("agora_mcp_abc");

        Assert.Equal(OAuthClients.StoredClientId("agora_mcp_abc"), stored);
        Assert.NotEqual(stored, OAuthClients.StoredClientId("agora_mcp_abd"));
        Assert.Matches("^mcp:[0-9a-f]{32}$", stored);
        Assert.True(stored.Length <= 64);
    }
}
