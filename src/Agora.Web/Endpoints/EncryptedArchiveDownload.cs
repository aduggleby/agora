using System.Security.Cryptography;
using Agora.Application.Utilities;

namespace Agora.Web.Endpoints;

/// <summary>
/// Serves a password-protected (.agz) archive: decrypts the object stream into a local scratch zip before the
/// response starts (so a wrong password can still redirect), then streams that plaintext and deletes it once the
/// response completes. The plaintext is deleted on every failure path before the response, too.
/// </summary>
public static class EncryptedArchiveDownload
{
    /// <returns>The result to return, or null when the password is wrong (nothing is left on disk).</returns>
    public static async Task<IResult?> ServeAsync(
        HttpContext context,
        Stream encryptedArchive,
        string password,
        string storageRoot,
        string downloadName,
        Func<Task> beforeResponse,
        CancellationToken ct)
    {
        var plaintextPath = ScratchFiles.NewPath(storageRoot, ".zip");
        try
        {
            await using (var output = File.Create(plaintextPath))
            {
                await ZipEncryption.DecryptAsync(encryptedArchive, output, password, ct);
            }

            await beforeResponse();
            var plaintext = File.OpenRead(plaintextPath);
            context.Response.OnCompleted(() =>
            {
                plaintext.Dispose();
                ScratchFiles.TryDelete(plaintextPath);
                return Task.CompletedTask;
            });
            return Results.File(plaintext, "application/zip", downloadName);
        }
        catch (CryptographicException)
        {
            ScratchFiles.TryDelete(plaintextPath);
            return null;
        }
        catch
        {
            ScratchFiles.TryDelete(plaintextPath);
            throw;
        }
    }
}
