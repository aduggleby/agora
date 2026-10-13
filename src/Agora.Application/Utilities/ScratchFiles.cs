namespace Agora.Application.Utilities;

/// <summary>
/// Local scratch files under <c>{StorageRoot}/tmp</c> (zip building, decryption, preview sources). Never durable:
/// callers delete them when done and the zombie cleanup sweeps leftovers older than the retention.
/// </summary>
public static class ScratchFiles
{
    public static string Root(string storageRoot) => Path.Combine(Path.GetFullPath(storageRoot), "tmp");

    public static string NewPath(string storageRoot, string extension) =>
        Path.Combine(Directory.CreateDirectory(Root(storageRoot)).FullName, $"{Guid.NewGuid():N}{extension}");

    public static void TryDelete(string? path)
    {
        try
        {
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
            // Swept later by the zombie cleanup.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
