using Agora.Application.Models;
using Agora.Web.Agents;
using Microsoft.Extensions.Options;

namespace Agora.Application.Tests;

public sealed class AgentTicketStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "agora-ticket-tests", Guid.NewGuid().ToString("N"));
    private readonly MutableClock _clock = new();
    private readonly AgentTicketStore _store;

    public AgentTicketStoreTests()
    {
        Directory.CreateDirectory(_root);
        _store = new AgentTicketStore(Options.Create(new AgoraOptions { StorageRoot = _root }), _clock);
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string TicketDirectory => Path.Combine(_root, "uploads", "agent-tickets");

    private AgentTicketStore.Ticket NewTicket() => new(
        AgentTicketStore.KindUpload, Guid.NewGuid(), _clock.GetUtcNow().UtcDateTime + AgentLimits.TicketLifetime,
        DraftId: "draft1", FileName: "a.txt", SizeBytes: 3);

    [Fact]
    public void Issued_ticket_is_read_without_being_used_and_claimed_once()
    {
        var plain = _store.Issue(NewTicket());

        Assert.Equal("a.txt", _store.Peek(plain)!.FileName);
        Assert.NotNull(_store.Peek(plain));
        Assert.Equal("draft1", _store.TryClaim(plain)!.DraftId);
        Assert.Null(_store.TryClaim(plain));
        Assert.Null(_store.Peek(plain));
        Assert.Empty(Directory.GetFiles(TicketDirectory));
    }

    [Fact]
    public async Task Concurrent_claims_have_exactly_one_winner()
    {
        var plain = _store.Issue(NewTicket());

        var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() => _store.TryClaim(plain))));

        Assert.Single(results, x => x is not null);
    }

    [Fact]
    public void An_expired_ticket_is_unknown()
    {
        var plain = _store.Issue(NewTicket());

        _clock.Advance(AgentLimits.TicketLifetime + TimeSpan.FromSeconds(1));

        Assert.Null(_store.Peek(plain));
        Assert.Null(_store.TryClaim(plain));
    }

    [Theory]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("../../../../etc/passwd/................................")]
    public void Malformed_tickets_never_reach_the_file_system(string plain)
    {
        Assert.Null(_store.Peek(plain));
        Assert.Null(_store.TryClaim(plain));
    }

    [Fact]
    public void Only_the_hash_is_stored()
    {
        var plain = _store.Issue(NewTicket());

        var file = Assert.Single(Directory.GetFiles(TicketDirectory));
        Assert.DoesNotContain(plain, Path.GetFileName(file), StringComparison.Ordinal);
        Assert.DoesNotContain(plain, File.ReadAllText(file), StringComparison.Ordinal);
        Assert.Equal(Agora.Application.Utilities.TokenCodec.HashToken(plain) + ".json", Path.GetFileName(file));
    }

    [Fact]
    public void Sweep_removes_expired_tickets_and_old_claim_leftovers_but_keeps_live_ones()
    {
        var live = _store.Issue(NewTicket());
        _clock.Advance(TimeSpan.FromMinutes(10));
        var later = _store.Issue(NewTicket());
        var leftover = Path.Combine(TicketDirectory, "x.json.claimed-1");
        File.WriteAllText(leftover, "{}");
        File.SetLastWriteTimeUtc(leftover, DateTime.UtcNow.AddMinutes(-5));
        _clock.Advance(TimeSpan.FromMinutes(6));

        var removed = _store.Sweep();

        Assert.Equal(2, removed);
        Assert.Null(_store.Peek(live));
        Assert.NotNull(_store.Peek(later));
        Assert.False(File.Exists(leftover));
    }

    internal sealed class MutableClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }
}
