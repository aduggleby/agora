using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Microsoft.Extensions.Options;

namespace Agora.Application.Tests;

public sealed class ShareContentStoreTests
{
    [Fact]
    public async Task PersistShareFilesAndResolvePath_Works()
    {
        var root = Path.Combine(Path.GetTempPath(), "agora-sharestore-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = Options.Create(new AgoraOptions { StorageRoot = root });
            IShareContentStore store = new ShareContentStore(options);

            var sourcePath = Path.Combine(root, "input.txt");
            await File.WriteAllTextAsync(sourcePath, "hello");
            var files = new List<UploadSourceFile>
            {
                new(sourcePath, "input.txt", 5, "text/plain")
            };

            var result = await store.PersistShareFilesAsync(files, DateTime.UtcNow, CancellationToken.None);
            Assert.Single(result.Files);
            var stored = result.Files[0];

            Assert.True(File.Exists(stored.StoredAbsolutePath));
            var resolved = store.ResolveAbsolutePath(stored.StoredRelativePath);
            Assert.Equal(Path.GetFullPath(stored.StoredAbsolutePath), resolved);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void ResolveAbsolutePath_RejectsTraversal()
    {
        var root = Path.Combine(Path.GetTempPath(), "agora-sharestore-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var options = Options.Create(new AgoraOptions { StorageRoot = root });
            IShareContentStore store = new ShareContentStore(options);
            Assert.Null(store.ResolveAbsolutePath("../../etc/passwd"));
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}
