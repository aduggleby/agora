using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;

namespace Agora.Application.Tests;

public sealed class ShareContentStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "agora-sharestore-tests", Guid.NewGuid().ToString("N"));

    public ShareContentStoreTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public async Task PersistShareFiles_uploads_to_object_keys_and_keeps_local_source()
    {
        var objectStore = new FileSystemObjectStore(Path.Combine(_root, "store"));
        IShareContentStore store = new ShareContentStore(objectStore);
        var sourcePath = Path.Combine(_root, "input.txt");
        await File.WriteAllTextAsync(sourcePath, "hello");

        var result = await store.PersistShareFilesAsync([new UploadSourceFile(sourcePath, "input.txt", 5, "text/plain")], new DateTime(2026, 10, 13, 0, 0, 0, DateTimeKind.Utc), CancellationToken.None);

        Assert.Matches("^shares/2026/10/[0-9a-f]{32}$", result.ContentRootPath);
        var stored = Assert.Single(result.Files);
        Assert.StartsWith(result.ContentRootPath + "/", stored.StoredRelativePath);
        Assert.EndsWith(".txt", stored.StoredRelativePath);
        Assert.Equal(sourcePath, stored.LocalSourcePath);
        Assert.Equal(5, (await objectStore.GetInfoAsync(stored.StoredRelativePath, CancellationToken.None))!.Length);
        Assert.True(File.Exists(sourcePath));
    }

    [Fact]
    public async Task PersistShareFiles_sanitises_and_deduplicates_entry_names()
    {
        IShareContentStore store = new ShareContentStore(new FileSystemObjectStore(Path.Combine(_root, "store")));
        var sourcePath = Path.Combine(_root, "input.txt");
        await File.WriteAllTextAsync(sourcePath, "hello");
        var now = new DateTime(2026, 10, 13, 0, 0, 0, DateTimeKind.Utc);

        var result = await store.PersistShareFilesAsync(
        [
            new UploadSourceFile(sourcePath, "a.txt", 5, "text/plain"),
            new UploadSourceFile(sourcePath, "A.TXT", 5, "text/plain"),
            new UploadSourceFile(sourcePath, "..\\evil.txt", 5, "text/plain"),
            new UploadSourceFile(sourcePath, "../../evil.txt", 5, "text/plain"),
        ], now, CancellationToken.None);

        Assert.Equal(["a.txt", "A (2).TXT", "evil.txt", "evil (2).txt"], result.Files.Select(x => x.EntryName).ToArray());
        Assert.All(result.Files, f => Assert.DoesNotContain("..", f.StoredRelativePath));
    }

    [Fact]
    public async Task PersistShareFiles_removes_partial_uploads_on_failure()
    {
        var storeRoot = Path.Combine(_root, "store");
        IShareContentStore store = new ShareContentStore(new FileSystemObjectStore(storeRoot));
        var sourcePath = Path.Combine(_root, "input.txt");
        await File.WriteAllTextAsync(sourcePath, "hello");
        var files = new List<UploadSourceFile>
        {
            new(sourcePath, "a.txt", 5, "text/plain"),
            new(Path.Combine(_root, "missing.txt"), "b.txt", 5, "text/plain")
        };

        await Assert.ThrowsAsync<FileNotFoundException>(() => store.PersistShareFilesAsync(files, DateTime.UtcNow, CancellationToken.None));

        Assert.Empty(Directory.EnumerateFiles(storeRoot, "*", SearchOption.AllDirectories));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("shares/")]
    [InlineData("shares/2026/10")]
    [InlineData("shares/2026/10/../..")]
    [InlineData("zips/2026/10/0123456789abcdef0123456789abcdef")]
    [InlineData("shares/2026/10/not-a-guid")]
    public async Task DeleteContentRoot_ignores_anything_but_generated_roots(string? contentRoot)
    {
        var storeRoot = Path.Combine(_root, "store");
        var objectStore = new FileSystemObjectStore(storeRoot);
        await objectStore.PutBytesAsync("shares/2026/10/0123456789abcdef0123456789abcdef/a.txt", [1], null, CancellationToken.None);
        await objectStore.PutBytesAsync("zips/2026/10/0123456789abcdef0123456789abcdef/a.txt", [1], null, CancellationToken.None);

        await new ShareContentStore(objectStore).DeleteContentRootAsync(contentRoot, CancellationToken.None);

        Assert.Equal(2, Directory.EnumerateFiles(storeRoot, "*", SearchOption.AllDirectories).Count());
    }

    [Fact]
    public async Task DeleteContentRoot_deletes_a_generated_root_only()
    {
        var storeRoot = Path.Combine(_root, "store");
        var objectStore = new FileSystemObjectStore(storeRoot);
        const string root = "shares/2026/10/0123456789abcdef0123456789abcdef";
        await objectStore.PutBytesAsync($"{root}/a.txt", [1], null, CancellationToken.None);
        await objectStore.PutBytesAsync($"{root}0/b.txt", [1], null, CancellationToken.None);

        await new ShareContentStore(objectStore).DeleteContentRootAsync(root, CancellationToken.None);

        Assert.Null(await objectStore.GetInfoAsync($"{root}/a.txt", CancellationToken.None));
        Assert.NotNull(await objectStore.GetInfoAsync($"{root}0/b.txt", CancellationToken.None));
    }
}
