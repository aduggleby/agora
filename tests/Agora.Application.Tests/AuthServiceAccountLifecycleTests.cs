using System.Data.Common;
using System.Diagnostics;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Agora.Application.Tests;

/// <summary>
/// Account lifecycle hardening: credential changes are atomic, invalidate every pending token, refuse stale
/// concurrent writes and notify the previous address; registration never reveals an existing account and lets only
/// the mailbox owner claim an unconfirmed one; sign-in failures are uniform.
/// </summary>
public sealed class AuthServiceAccountLifecycleTests
{
    private const string Email = "user@example.com";
    private const string Password = "CorrectHorseBatteryStaple!";
    private const string Token = "single-use-token";
    private const string ConfirmUrl = "https://files.example.com/auth/confirm-email";
    private const string Ip = "203.0.113.1";

    [Fact]
    public async Task ConfirmEmailChange_notifies_the_old_address_clears_pending_tokens_and_re_addresses_owned_rows()
    {
        await using var harness = await Harness.CreateAsync();
        var user = await harness.UserAsync();
        user.PendingEmail = "renamed@example.com";
        user.PendingEmailTokenHash = TokenCodec.HashToken(Token);
        user.PendingEmailTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        SetOtherPendingTokens(user);
        harness.Db.Shares.Add(NewShare(user.Id, Email, "owned"));
        harness.Db.Shares.Add(NewShare(null, Email, "unowned"));
        harness.Db.Shares.Add(NewShare(Guid.NewGuid(), Email, "foreign"));
        harness.Db.AccountTemplates.Add(new AccountTemplate { Id = Guid.NewGuid(), OwnerUserId = user.Id, UploaderEmail = Email, Title = $"by {Email}", UpdatedAtUtc = DateTime.UtcNow });
        await harness.Db.SaveChangesAsync();

        var result = await harness.Service.ConfirmEmailChangeAsync(Email, Token, CancellationToken.None);

        Assert.True(result.Success, result.Error);
        Assert.Equal("renamed@example.com", user.Email);
        AssertNoPendingTokens(user);

        var toOld = Assert.Single(harness.Emails.Sent, x => x.To == Email);
        Assert.Contains("renamed@example.com", toOld.IntroText);
        Assert.Single(harness.Emails.Sent, x => x.To == "renamed@example.com");

        harness.Db.ChangeTracker.Clear();
        var shares = await harness.Db.Shares.ToDictionaryAsync(x => x.ShareToken);
        Assert.Equal(("renamed@example.com", (Guid?)user.Id), (shares["owned"].UploaderEmail, shares["owned"].OwnerUserId));
        Assert.Equal((Email, (Guid?)null), (shares["unowned"].UploaderEmail, shares["unowned"].OwnerUserId));
        Assert.Equal(Email, shares["foreign"].UploaderEmail);
        var template = await harness.Db.AccountTemplates.SingleAsync();
        Assert.Equal(("renamed@example.com", "by renamed@example.com"), (template.UploaderEmail, template.Title));
    }

    [Fact]
    public async Task ConfirmEmailChange_reclaims_an_orphaned_template_at_the_new_address()
    {
        await using var harness = await Harness.CreateAsync();
        var user = await harness.UserAsync();
        user.PendingEmail = "renamed@example.com";
        user.PendingEmailTokenHash = TokenCodec.HashToken(Token);
        user.PendingEmailTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        var own = new AccountTemplate { Id = Guid.NewGuid(), OwnerUserId = user.Id, UploaderEmail = Email, Title = "Mine", UpdatedAtUtc = DateTime.UtcNow };
        var orphan = new AccountTemplate { Id = Guid.NewGuid(), OwnerUserId = null, UploaderEmail = "renamed@example.com", Title = "Orphan", UpdatedAtUtc = DateTime.UtcNow };
        harness.Db.AccountTemplates.AddRange(own, orphan);
        await harness.Db.SaveChangesAsync();

        var result = await harness.Service.ConfirmEmailChangeAsync(Email, Token, CancellationToken.None);

        Assert.True(result.Success, result.Error);
        harness.Db.ChangeTracker.Clear();
        var row = await harness.Db.AccountTemplates.SingleAsync();
        Assert.Equal((own.Id, "renamed@example.com", "Mine"), (row.Id, row.UploaderEmail, row.Title));
    }

    [Fact]
    public async Task ConfirmEmailChange_rolls_everything_back_when_the_share_update_fails()
    {
        await using var harness = await Harness.CreateAsync(new FailSharesUpdateInterceptor());
        var user = await harness.UserAsync();
        user.PendingEmail = "renamed@example.com";
        user.PendingEmailTokenHash = TokenCodec.HashToken(Token);
        user.PendingEmailTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        var stampBefore = user.SecurityStamp;
        harness.Db.Shares.Add(NewShare(user.Id, Email, "owned"));
        harness.Db.AccountTemplates.Add(new AccountTemplate { Id = Guid.NewGuid(), OwnerUserId = user.Id, UploaderEmail = Email, UpdatedAtUtc = DateTime.UtcNow });
        await harness.Db.SaveChangesAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.ConfirmEmailChangeAsync(Email, Token, CancellationToken.None));

        await using var fresh = harness.NewContext();
        var stored = await fresh.Users.SingleAsync();
        Assert.Equal(Email, stored.Email);
        Assert.Equal("renamed@example.com", stored.PendingEmail);
        Assert.Equal(TokenCodec.HashToken(Token), stored.PendingEmailTokenHash);
        Assert.Equal(stampBefore, stored.SecurityStamp);
        Assert.Equal(Email, (await fresh.AccountTemplates.SingleAsync()).UploaderEmail);
        Assert.Equal(Email, (await fresh.Shares.SingleAsync()).UploaderEmail);
        Assert.Empty(harness.Emails.Sent);
    }

    [Fact]
    public async Task Email_change_confirmation_with_a_stale_user_fails_after_a_concurrent_password_reset()
    {
        await using var harness = await Harness.CreateAsync();
        var user = await harness.UserAsync();
        user.PendingEmail = "renamed@example.com";
        user.PendingEmailTokenHash = TokenCodec.HashToken(Token);
        user.PendingEmailTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        user.PasswordResetTokenHash = TokenCodec.HashToken("reset");
        user.PasswordResetTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        await harness.Db.SaveChangesAsync();

        // Context A loads the user (as the email-change handler would), context B resets the password and commits.
        var staleService = harness.Service;
        _ = await harness.UserAsync();
        await using var other = harness.NewContext();
        var reset = await new AuthService(other, harness.Emails).ResetPasswordAsync(Email, "reset", "AnotherPassword123!", CancellationToken.None);
        Assert.True(reset.Success, reset.Error);

        var change = await staleService.ConfirmEmailChangeAsync(Email, Token, CancellationToken.None);

        Assert.False(change.Success);
        Assert.Equal("This confirmation link is invalid or expired.", change.Error);
        await using var fresh = harness.NewContext();
        var stored = await fresh.Users.SingleAsync();
        Assert.Equal(Email, stored.Email);
        Assert.Null(stored.PendingEmail);
        Assert.True(PasswordHasher.Verify("AnotherPassword123!", stored.PasswordHash));
    }

    [Fact]
    public async Task ResetPassword_clears_a_pending_email_change()
    {
        await using var harness = await Harness.CreateAsync();
        var user = await harness.UserAsync();
        user.PasswordResetTokenHash = TokenCodec.HashToken(Token);
        user.PasswordResetTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        user.PendingEmail = "attacker@example.com";
        user.PendingEmailTokenHash = TokenCodec.HashToken("attacker-token");
        user.PendingEmailTokenExpiresAtUtc = DateTime.UtcNow.AddHours(20);
        await harness.Db.SaveChangesAsync();

        var reset = await harness.Service.ResetPasswordAsync(Email, Token, "AnotherPassword123!", CancellationToken.None);
        Assert.True(reset.Success, reset.Error);
        AssertNoPendingTokens(user);

        var finish = await harness.Service.ConfirmEmailChangeAsync(Email, "attacker-token", CancellationToken.None);
        Assert.False(finish.Success);
        Assert.Equal(Email, user.Email);
    }

    [Fact]
    public async Task ConfirmPasswordChange_clears_reset_and_email_change_tokens()
    {
        await using var harness = await Harness.CreateAsync();
        var user = await harness.UserAsync();
        user.PendingPasswordHash = PasswordHasher.Hash("AnotherPassword123!");
        user.PendingPasswordTokenHash = TokenCodec.HashToken(Token);
        user.PendingPasswordTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        user.PasswordResetTokenHash = TokenCodec.HashToken("reset");
        user.PasswordResetTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        user.PendingEmail = "attacker@example.com";
        user.PendingEmailTokenHash = TokenCodec.HashToken("attacker-token");
        user.PendingEmailTokenExpiresAtUtc = DateTime.UtcNow.AddHours(20);
        await harness.Db.SaveChangesAsync();

        var result = await harness.Service.ConfirmPasswordChangeAsync(Email, Token, CancellationToken.None);

        Assert.True(result.Success, result.Error);
        Assert.True(PasswordHasher.Verify("AnotherPassword123!", user.PasswordHash));
        AssertNoPendingTokens(user);
    }

    [Fact]
    public async Task Register_unconfirmed_account_is_claimed_by_the_mailbox_owner_with_their_own_password()
    {
        await using var harness = await Harness.CreateAsync();

        // The attacker registers the victim's address first.
        var attacker = await harness.Service.RegisterAsync("victim@example.com", "AttackerChosen123!", ConfirmUrl, CancellationToken.None);
        Assert.True(attacker.Success, attacker.Error);
        var attackerLink = Assert.Single(harness.Emails.Sent).ActionUrl!;
        var attackerToken = TokenFromLink(attackerLink);
        var stampBefore = (await harness.Db.Users.SingleAsync(x => x.Email == "victim@example.com")).SecurityStamp;

        // The victim registers second; the response is the same "check your email" outcome.
        var victim = await harness.Service.RegisterAsync("victim@example.com", "VictimChosen123!", ConfirmUrl, CancellationToken.None);
        Assert.True(victim.Success, victim.Error);
        Assert.Equal(2, harness.Emails.Sent.Count);
        var victimToken = TokenFromLink(harness.Emails.Sent[1].ActionUrl!);
        Assert.NotEqual(attackerToken, victimToken);
        Assert.Equal(1, await harness.Db.Users.CountAsync(x => x.Email == "victim@example.com"));
        Assert.NotEqual(stampBefore, (await harness.Db.Users.SingleAsync(x => x.Email == "victim@example.com")).SecurityStamp);

        // The attacker's earlier link is dead; the victim's works and activates the victim's password only.
        Assert.False((await harness.Service.ConfirmEmailAsync("victim@example.com", attackerToken, CancellationToken.None)).Success);
        var confirmed = await harness.Service.ConfirmEmailAsync("victim@example.com", victimToken, CancellationToken.None);
        Assert.True(confirmed.Success, confirmed.Error);
        Assert.False((await harness.Service.LoginAsync("victim@example.com", "AttackerChosen123!", Ip, CancellationToken.None)).Success);
        Assert.True((await harness.Service.LoginAsync("victim@example.com", "VictimChosen123!", Ip, CancellationToken.None)).Success);
    }

    [Fact]
    public async Task Confirmation_rotates_the_stamp_so_a_stale_claim_cannot_replace_the_confirmed_password()
    {
        await using var harness = await Harness.CreateAsync();
        var victim = await harness.Service.RegisterAsync("victim@example.com", "VictimChosen123!", ConfirmUrl, CancellationToken.None);
        Assert.True(victim.Success, victim.Error);
        var victimToken = TokenFromLink(Assert.Single(harness.Emails.Sent).ActionUrl!);

        // The attacker's registration has already loaded the (still unconfirmed) row when the victim confirms.
        await using var attackerContext = harness.NewContext();
        var attackerService = new AuthService(attackerContext, harness.Emails);
        _ = await attackerContext.Users.SingleAsync(x => x.Email == "victim@example.com");

        var confirmed = await harness.Service.ConfirmEmailAsync("victim@example.com", victimToken, CancellationToken.None);
        Assert.True(confirmed.Success, confirmed.Error);

        var attacker = await attackerService.RegisterAsync("victim@example.com", "AttackerChosen123!", ConfirmUrl, CancellationToken.None);
        Assert.True(attacker.Success, attacker.Error); // same response, but the stale save was refused

        await using var fresh = harness.NewContext();
        var stored = await fresh.Users.SingleAsync(x => x.Email == "victim@example.com");
        Assert.True(stored.EmailConfirmed);
        Assert.True(PasswordHasher.Verify("VictimChosen123!", stored.PasswordHash));
        Assert.False(PasswordHasher.Verify("AttackerChosen123!", stored.PasswordHash));
        Assert.Null(stored.EmailConfirmationTokenHash);
        Assert.Single(harness.Emails.Sent);
    }

    [Fact]
    public async Task Authenticated_profile_update_with_a_stale_user_returns_a_controlled_failure()
    {
        await using var harness = await Harness.CreateAsync();
        var user = await harness.UserAsync();
        user.PasswordResetTokenHash = TokenCodec.HashToken("reset");
        user.PasswordResetTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        await harness.Db.SaveChangesAsync();

        // Context A (the settings page) holds the user; context B resets the password in between.
        await using var other = harness.NewContext();
        var reset = await new AuthService(other, harness.Emails).ResetPasswordAsync(Email, "reset", "AnotherPassword123!", CancellationToken.None);
        Assert.True(reset.Success, reset.Error);

        var rename = await harness.Service.SetDisplayNameAsync(user.Id, "Stale Name", CancellationToken.None);
        // The stale row still verifies the old password; the save is what fails.
        var emailChange = await harness.Service.RequestEmailChangeAsync(user.Id, "renamed@example.com", Password, ConfirmUrl, CancellationToken.None);

        Assert.Equal((false, AuthService.TryAgainError, (string?)null), rename);
        Assert.Equal((false, AuthService.TryAgainError), emailChange);
        await using var fresh = harness.NewContext();
        var stored = await fresh.Users.SingleAsync();
        Assert.NotEqual("Stale Name", stored.DisplayName);
        Assert.Null(stored.PendingEmail);
        // Nothing was queued for the refused requests (only the reset notice).
        Assert.Single(harness.Emails.Sent);
    }

    [Fact]
    public async Task Register_existing_disabled_unconfirmed_account_is_untouched_and_sends_nothing()
    {
        await using var harness = await Harness.CreateAsync();
        var user = await harness.UserAsync();
        user.EmailConfirmed = false;
        user.IsEnabled = false;
        await harness.Db.SaveChangesAsync();
        var hashBefore = user.PasswordHash;

        var result = await harness.Service.RegisterAsync(Email, "AttackerChosen123!", ConfirmUrl, CancellationToken.None);

        Assert.True(result.Success, result.Error);
        Assert.False(user.IsEnabled);
        Assert.Equal(hashBefore, user.PasswordHash);
        Assert.Null(user.EmailConfirmationTokenHash);
        Assert.Empty(harness.Emails.Sent);
    }

    [Fact]
    public async Task Register_existing_confirmed_account_succeeds_without_changes_and_notifies_the_owner()
    {
        await using var harness = await Harness.CreateAsync();
        var user = await harness.UserAsync();
        var hashBefore = user.PasswordHash;

        var result = await harness.Service.RegisterAsync(Email, "AttackerChosen123!", ConfirmUrl, CancellationToken.None);

        Assert.True(result.Success, result.Error);
        Assert.Equal(hashBefore, user.PasswordHash);
        Assert.Null(user.EmailConfirmationTokenHash);
        var sent = Assert.Single(harness.Emails.Sent);
        Assert.Equal(Email, sent.To);
        Assert.Null(sent.ActionUrl);
        Assert.Contains("already", sent.Subject, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, await harness.Db.Users.CountAsync());
    }

    [Fact]
    public async Task Register_stamps_the_template_and_reuses_an_orphaned_row_with_defaults()
    {
        await using var harness = await Harness.CreateAsync();
        var orphan = new AccountTemplate
        {
            Id = Guid.NewGuid(),
            OwnerUserId = null,
            UploaderEmail = "newcomer@example.com",
            Title = "Previous owner's title",
            BackgroundImageUrl = "internal:backgrounds/previous.png",
            UpdatedAtUtc = DateTime.UtcNow.AddDays(-30)
        };
        harness.Db.AccountTemplates.Add(orphan);
        await harness.Db.SaveChangesAsync();

        var result = await harness.Service.RegisterAsync("newcomer@example.com", Password, ConfirmUrl, CancellationToken.None);

        Assert.True(result.Success, result.Error);
        var user = await harness.Db.Users.SingleAsync(x => x.Email == "newcomer@example.com");
        var template = await harness.Db.AccountTemplates.SingleAsync(x => x.UploaderEmail == "newcomer@example.com");
        Assert.Equal(orphan.Id, template.Id);
        Assert.Equal(user.Id, template.OwnerUserId);
        Assert.Equal("by newcomer@example.com", template.Title);
        Assert.Null(template.BackgroundImageUrl);
    }

    [Fact]
    public async Task Delete_user_removes_its_shares_and_template_so_a_re_registered_address_inherits_nothing()
    {
        await using var harness = await Harness.CreateAsync();
        var admin = await harness.UserAsync();
        admin.Role = "admin";
        var victim = new UserAccount
        {
            Id = Guid.NewGuid(),
            Email = "victim@example.com",
            EmailConfirmed = true,
            PasswordHash = PasswordHasher.Hash(Password),
            SecurityStamp = SecurityStamps.New(),
            UploadToken = "victim01",
            CreatedAtUtc = DateTime.UtcNow
        };
        harness.Db.Users.Add(victim);
        harness.Db.AccountTemplates.Add(new AccountTemplate { Id = Guid.NewGuid(), OwnerUserId = victim.Id, UploaderEmail = victim.Email, UpdatedAtUtc = DateTime.UtcNow });
        harness.Db.Shares.Add(NewShare(victim.Id, victim.Email, "victim-share"));
        harness.Db.Shares.Add(NewShare(admin.Id, admin.Email, "admin-share"));
        await harness.Db.SaveChangesAsync();

        Assert.True(await harness.Service.DeleteUserAsync(victim.Id, CancellationToken.None));

        Assert.Empty(await harness.Db.AccountTemplates.Where(x => x.UploaderEmail == "victim@example.com").ToListAsync());
        var share = await harness.Db.Shares.SingleAsync(x => x.ShareToken == "victim-share");
        Assert.NotNull(share.DeletedAtUtc);
        Assert.Equal(victim.Id, share.OwnerUserId);
        Assert.Null((await harness.Db.Shares.SingleAsync(x => x.ShareToken == "admin-share")).DeletedAtUtc);
        Assert.Equal([share.Id], harness.Jobs.DeletedShareIds);

        var registered = await harness.Service.RegisterAsync("victim@example.com", Password, ConfirmUrl, CancellationToken.None);
        Assert.True(registered.Success, registered.Error);
        var newcomer = await harness.Db.Users.SingleAsync(x => x.Email == "victim@example.com");
        Assert.NotEqual(victim.Id, newcomer.Id);
        Assert.False(ShareOwner.For(newcomer.Id, newcomer.Email).Owns(share.OwnerUserId));
        Assert.Equal(0, await harness.Db.Shares.CountAsync(x => x.OwnerUserId == newcomer.Id));
    }

    [Fact]
    public async Task Login_returns_one_message_for_unknown_wrong_disabled_and_locked()
    {
        await using var harness = await Harness.CreateAsync();

        var unknown = await harness.Service.LoginAsync("nobody@example.com", Password, Ip, CancellationToken.None);
        var wrong = await harness.Service.LoginAsync(Email, "wrong-password", Ip, CancellationToken.None);

        var user = await harness.UserAsync();
        user.IsEnabled = false;
        await harness.Db.SaveChangesAsync();
        var disabled = await harness.Service.LoginAsync(Email, Password, Ip, CancellationToken.None);

        user.IsEnabled = true;
        await harness.Db.SaveChangesAsync();
        for (var i = 0; i < LoginLockouts.MaxFailures; i++)
        {
            await harness.Service.LoginAsync(Email, "wrong-password", Ip, CancellationToken.None);
        }

        var locked = await harness.Service.LoginAsync(Email, Password, Ip, CancellationToken.None);

        Assert.All([unknown, wrong, disabled, locked], result =>
        {
            Assert.False(result.Success);
            Assert.Null(result.User);
            Assert.Equal(AuthService.LoginFailedError, result.Error);
        });
    }

    [Fact]
    public async Task Login_reveals_an_unconfirmed_account_only_to_the_correct_password_and_accumulates_nothing()
    {
        await using var harness = await Harness.CreateAsync();
        var user = await harness.UserAsync();
        user.EmailConfirmed = false;
        await harness.Db.SaveChangesAsync();

        for (var i = 0; i < LoginLockouts.MaxFailures + 1; i++)
        {
            Assert.Equal(AuthService.LoginFailedError, (await harness.Service.LoginAsync(Email, "wrong-password", Ip, CancellationToken.None)).Error);
        }

        var right = await harness.Service.LoginAsync(Email, Password, Ip, CancellationToken.None);

        Assert.Equal(AuthService.EmailConfirmationRequiredError, right.Error);
        Assert.Equal(0, user.FailedLoginCount);
        Assert.Null(user.LastFailedLoginAtUtc);
    }

    [Fact]
    public async Task Login_for_an_unknown_address_costs_a_password_verification()
    {
        await using var harness = await Harness.CreateAsync();
        // Warm up (type initialisation, first PBKDF2) before measuring.
        await harness.Service.LoginAsync("nobody@example.com", Password, Ip, CancellationToken.None);
        await harness.Service.LoginAsync(Email, "wrong-password", Ip, CancellationToken.None);

        var unknown = await MedianAsync(() => harness.Service.LoginAsync("nobody@example.com", Password, Ip, CancellationToken.None));
        var known = await MedianAsync(() => harness.Service.LoginAsync(Email, "wrong-password", Ip, CancellationToken.None));

        // Without the dummy verification the unknown path is a single indexed lookup, orders of magnitude below one
        // PBKDF2 run; the bound is loose on purpose so a busy machine cannot flake it.
        Assert.True(unknown >= known * 0.5, $"unknown-address login took {unknown}ms, wrong-password login {known}ms");
    }

    [Fact]
    public async Task Link_handlers_do_not_distinguish_unknown_addresses_from_bad_tokens()
    {
        await using var harness = await Harness.CreateAsync();

        var confirmUnknown = await harness.Service.ConfirmEmailAsync("nobody@example.com", Token, CancellationToken.None);
        var confirmBadToken = await harness.Service.ConfirmEmailAsync(Email, Token, CancellationToken.None);
        Assert.Equal(confirmUnknown, confirmBadToken);
        Assert.False(confirmBadToken.Success);

        var resetUnknown = await harness.Service.ResetPasswordAsync("nobody@example.com", Token, Password, CancellationToken.None);
        var resetBadToken = await harness.Service.ResetPasswordAsync(Email, Token, Password, CancellationToken.None);
        Assert.Equal(resetUnknown, resetBadToken);
        Assert.False(resetBadToken.Success);

        var changeUnknown = await harness.Service.ConfirmEmailChangeAsync("nobody@example.com", Token, CancellationToken.None);
        var changeBadToken = await harness.Service.ConfirmEmailChangeAsync(Email, Token, CancellationToken.None);
        Assert.Equal(changeUnknown, changeBadToken);

        var passwordUnknown = await harness.Service.ConfirmPasswordChangeAsync("nobody@example.com", Token, CancellationToken.None);
        var passwordBadToken = await harness.Service.ConfirmPasswordChangeAsync(Email, Token, CancellationToken.None);
        Assert.Equal(passwordUnknown, passwordBadToken);
    }

    private static string TokenFromLink(string link)
    {
        var query = new Uri(link).Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries);
        var token = query.Single(x => x.StartsWith("token=", StringComparison.Ordinal))["token=".Length..];
        return Uri.UnescapeDataString(token);
    }

    private static async Task<double> MedianAsync(Func<Task> action)
    {
        var samples = new List<double>();
        for (var i = 0; i < 3; i++)
        {
            var watch = Stopwatch.StartNew();
            await action();
            samples.Add(watch.Elapsed.TotalMilliseconds);
        }

        samples.Sort();
        return samples[1];
    }

    private static void SetOtherPendingTokens(UserAccount user)
    {
        user.EmailConfirmationTokenHash = TokenCodec.HashToken("confirm");
        user.EmailConfirmationTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        user.PendingPasswordHash = PasswordHasher.Hash("Pending123!");
        user.PendingPasswordTokenHash = TokenCodec.HashToken("pending-password");
        user.PendingPasswordTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        user.PasswordResetTokenHash = TokenCodec.HashToken("reset");
        user.PasswordResetTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
    }

    private static void AssertNoPendingTokens(UserAccount user)
    {
        Assert.Null(user.EmailConfirmationTokenHash);
        Assert.Null(user.EmailConfirmationTokenExpiresAtUtc);
        Assert.Null(user.PendingEmail);
        Assert.Null(user.PendingEmailTokenHash);
        Assert.Null(user.PendingEmailTokenExpiresAtUtc);
        Assert.Null(user.PendingPasswordHash);
        Assert.Null(user.PendingPasswordTokenHash);
        Assert.Null(user.PendingPasswordTokenExpiresAtUtc);
        Assert.Null(user.PasswordResetTokenHash);
        Assert.Null(user.PasswordResetTokenExpiresAtUtc);
    }

    private static Share NewShare(Guid? ownerUserId, string uploaderEmail, string token) => new()
    {
        Id = Guid.NewGuid(),
        OwnerUserId = ownerUserId,
        UploaderEmail = uploaderEmail,
        ShareToken = token,
        ZipDisplayName = "files.zip",
        ZipDiskPath = "zips/2026/10/x.zip",
        ZipSizeBytes = 1,
        NotifyMode = "none",
        CreatedAtUtc = DateTime.UtcNow
    };

    /// <summary>Fails the bulk UPDATE of the Shares table so the surrounding transaction must roll back.</summary>
    private sealed class FailSharesUpdateInterceptor : DbCommandInterceptor
    {
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("UPDATE \"Shares\"", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Simulated failure of the share update.");
            }

            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly DbContextOptions<AgoraDbContext> _options;

        public AgoraDbContext Db { get; }
        public AuthService Service { get; }
        public RecordingEmailSender Emails { get; } = new();
        public RecordingJobClient Jobs { get; }

        private Harness(SqliteConnection connection, DbContextOptions<AgoraDbContext> options, AgoraDbContext db)
        {
            _connection = connection;
            _options = options;
            Db = db;
            Jobs = new RecordingJobClient(Emails);
            Service = new AuthService(db, Emails, Jobs);
        }

        public static async Task<Harness> CreateAsync(IInterceptor? interceptor = null)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var builder = new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection);
            if (interceptor is not null)
            {
                builder.AddInterceptors(interceptor);
            }

            var options = builder.Options;
            var db = new AgoraDbContext(options);
            await db.Database.EnsureCreatedAsync();
            db.Users.Add(new UserAccount
            {
                Id = Guid.NewGuid(),
                Email = Email,
                EmailConfirmed = true,
                PasswordHash = PasswordHasher.Hash(Password),
                SecurityStamp = SecurityStamps.New(),
                Role = "user",
                IsEnabled = true,
                UploadToken = "seeduser",
                CreatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
            return new Harness(connection, options, db);
        }

        /// <summary>A second context over the same in-memory database (a concurrent request).</summary>
        public AgoraDbContext NewContext() => new(_options);

        public Task<UserAccount> UserAsync() => Db.Users.SingleAsync(x => x.Email == Email);

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        public List<AuthEmailMessage> Sent { get; } = [];

        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken)
        {
            Sent.Add(message);
            return Task.CompletedTask;
        }
    }

    /// <summary>Delivers queued auth emails to the recording sender and records queued share-content deletions.</summary>
    private sealed class RecordingJobClient(RecordingEmailSender emails) : IBackgroundJobClient
    {
        public List<Guid> DeletedShareIds { get; } = [];

        public string Create(Job job, IState state)
        {
            if (job.Method.Name == nameof(Infrastructure.Services.ShareManager.DeleteShareFilesAsync) && job.Args[0] is Guid shareId)
            {
                DeletedShareIds.Add(shareId);
            }
            else if (job.Args.Count > 0 && job.Args[0] is AuthEmailMessage message)
            {
                emails.Sent.Add(message);
            }

            return Guid.NewGuid().ToString("N");
        }

        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }
}
