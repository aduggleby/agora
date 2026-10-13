namespace Agora.Application.Models;

/// <summary>
/// A share could not be saved because its token is already taken. Deliberately carries neither the token nor the
/// database error (whose text quotes the duplicate key), only the violated constraint's name.
/// </summary>
public sealed class ShareTokenCollisionException(string constraintName)
    : Exception("Share token is already in use.")
{
    public string ConstraintName { get; } = constraintName;
}
