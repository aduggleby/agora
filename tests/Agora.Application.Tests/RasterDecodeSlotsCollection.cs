namespace Agora.Application.Tests;

/// <summary>
/// Test classes that hold the shared static raster decode slots (or run decodes on a one-second budget) run one after
/// another, so a test holding both slots never times out a decode in another class.
/// </summary>
[CollectionDefinition(Name)]
public sealed class RasterDecodeSlotsCollection
{
    public const string Name = "Raster decode slots";
}
