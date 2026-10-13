using Agora.Domain.Entities;
using Agora.Infrastructure.Services;

namespace Agora.Web.Services;

public sealed record ShareExperiencePresentation(
    string ExperienceType,
    bool AllowsPreview,
    bool AllowsZipDownload,
    IReadOnlyList<ShareFile> PreviewFiles,
    IReadOnlyList<ShareFile> GalleryFiles);

public interface IShareExperienceRenderer
{
    string ExperienceType { get; }
    ShareExperiencePresentation Build(Share share);
}

public sealed class ArchiveShareExperienceRenderer : IShareExperienceRenderer
{
    public string ExperienceType => "archive";

    public ShareExperiencePresentation Build(Share share)
    {
        var allowsPreview = ShareManager.AllowsPreview(share);
        return new ShareExperiencePresentation(
            ExperienceType,
            allowsPreview,
            ShareManager.AllowsZipDownload(share),
            allowsPreview ? share.Files.ToList() : [],
            []);
    }
}

public sealed class GalleryShareExperienceRenderer : IShareExperienceRenderer
{
    public string ExperienceType => "gallery";

    public ShareExperiencePresentation Build(Share share)
    {
        var allowsPreview = ShareManager.AllowsPreview(share);
        return new ShareExperiencePresentation(
            ExperienceType,
            allowsPreview,
            ShareManager.AllowsZipDownload(share),
            allowsPreview ? share.Files.ToList() : [],
            allowsPreview
                ? share.Files.Where(file => string.Equals(file.RenderType, "image", StringComparison.OrdinalIgnoreCase)).ToList()
                : []);
    }
}

public sealed class ShareExperienceRendererResolver(IEnumerable<IShareExperienceRenderer> renderers)
{
    private readonly Dictionary<string, IShareExperienceRenderer> _renderers = renderers
        .ToDictionary(x => x.ExperienceType, x => x, StringComparer.OrdinalIgnoreCase);

    public ShareExperiencePresentation Resolve(Share share)
    {
        var key = ShareManager.NormalizeShareExperienceType(share.ShareExperienceType);
        if (_renderers.TryGetValue(key, out var renderer))
        {
            return renderer.Build(share);
        }

        return _renderers["archive"].Build(share);
    }
}
