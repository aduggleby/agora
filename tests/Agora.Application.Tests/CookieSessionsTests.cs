using System.Security.Claims;
using Agora.Domain.Entities;
using Agora.Web.Auth;

namespace Agora.Application.Tests;

public sealed class CookieSessionsTests
{
    private static readonly DateTime Now = new(2026, 10, 13, 12, 0, 0, DateTimeKind.Utc);
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    [Fact]
    public void CreatePrincipal_CarriesIdentityRoleStampAndTimestamp()
    {
        var user = NewUser();

        var principal = CookieSessions.CreatePrincipal(user, Now);

        Assert.Equal(user.Id.ToString(), principal.FindFirstValue(ClaimTypes.NameIdentifier));
        Assert.Equal(user.Email, principal.FindFirstValue(ClaimTypes.Email));
        Assert.Equal("Someone", principal.FindFirstValue(ClaimTypes.Name));
        Assert.True(principal.IsInRole("user"));
        Assert.Equal(user.SecurityStamp, principal.FindFirstValue(CookieSessions.SecurityStampClaim));
        Assert.False(CookieSessions.IsRevalidationDue(principal, Now, Interval));
    }

    [Fact]
    public void IsRevalidationDue_WithinInterval_IsFalse()
    {
        var principal = CookieSessions.CreatePrincipal(NewUser(), Now);

        Assert.False(CookieSessions.IsRevalidationDue(principal, Now.AddMinutes(4), Interval));
    }

    [Fact]
    public void IsRevalidationDue_AfterInterval_IsTrue()
    {
        var principal = CookieSessions.CreatePrincipal(NewUser(), Now);

        Assert.True(CookieSessions.IsRevalidationDue(principal, Now.AddMinutes(5), Interval));
    }

    [Fact]
    public void IsRevalidationDue_ZeroInterval_ChecksEveryRequest()
    {
        var principal = CookieSessions.CreatePrincipal(NewUser(), Now);

        Assert.True(CookieSessions.IsRevalidationDue(principal, Now, TimeSpan.Zero));
    }

    [Fact]
    public void IsRevalidationDue_MissingOrFutureTimestamp_IsTrue()
    {
        var legacy = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Email, "user@example.com")], "Cookies"));
        Assert.True(CookieSessions.IsRevalidationDue(legacy, Now, Interval));

        var garbage = new ClaimsPrincipal(new ClaimsIdentity([new Claim(CookieSessions.RevalidatedAtClaim, "not-a-date")], "Cookies"));
        Assert.True(CookieSessions.IsRevalidationDue(garbage, Now, Interval));

        var future = CookieSessions.CreatePrincipal(NewUser(), Now.AddMinutes(1));
        Assert.True(CookieSessions.IsRevalidationDue(future, Now, Interval));
    }

    [Fact]
    public void Validate_MatchingStamp_Refreshes()
    {
        var user = NewUser();
        var principal = CookieSessions.CreatePrincipal(user, Now);

        Assert.Equal(SessionCheck.Refresh, CookieSessions.Validate(principal, user));
    }

    [Fact]
    public void Validate_RefreshedPrincipalFollowsDatabaseRole()
    {
        var user = NewUser();
        var principal = CookieSessions.CreatePrincipal(user, Now);
        Assert.True(principal.IsInRole("user"));

        user.Role = "admin";
        Assert.Equal(SessionCheck.Refresh, CookieSessions.Validate(principal, user));
        var refreshed = CookieSessions.CreatePrincipal(user, Now.AddMinutes(5));

        Assert.True(refreshed.IsInRole("admin"));
        Assert.False(refreshed.IsInRole("user"));
    }

    [Fact]
    public void Validate_MissingUser_Rejects()
    {
        var principal = CookieSessions.CreatePrincipal(NewUser(), Now);

        Assert.Equal(SessionCheck.Reject, CookieSessions.Validate(principal, null));
    }

    [Fact]
    public void Validate_DisabledUser_Rejects()
    {
        var user = NewUser();
        var principal = CookieSessions.CreatePrincipal(user, Now);
        user.IsEnabled = false;

        Assert.Equal(SessionCheck.Reject, CookieSessions.Validate(principal, user));
    }

    [Fact]
    public void Validate_RotatedStamp_Rejects()
    {
        var user = NewUser();
        var principal = CookieSessions.CreatePrincipal(user, Now);
        user.SecurityStamp = "rotated";

        Assert.Equal(SessionCheck.Reject, CookieSessions.Validate(principal, user));
    }

    [Fact]
    public void Validate_PreStampCookie_Rejects()
    {
        var user = NewUser();
        var legacy = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, "admin")
            ],
            "Cookies"));

        Assert.Equal(SessionCheck.Reject, CookieSessions.Validate(legacy, user));
    }

    [Fact]
    public void Validate_UserWithoutStamp_Rejects()
    {
        var user = NewUser();
        var principal = CookieSessions.CreatePrincipal(user, Now);
        user.SecurityStamp = string.Empty;

        Assert.Equal(SessionCheck.Reject, CookieSessions.Validate(principal, user));
    }

    private static UserAccount NewUser() => new()
    {
        Id = Guid.NewGuid(),
        Email = "user@example.com",
        DisplayName = "Someone",
        Role = "user",
        IsEnabled = true,
        SecurityStamp = "stamp-1",
        CreatedAtUtc = Now
    };
}
