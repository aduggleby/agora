using Agora.Application.Models;

namespace Agora.Web.Agents;

/// <summary>
/// What an agent service call returns: a value, or a refusal with an HTTP status and a message. HTTP routes map it
/// with <see cref="ToHttp"/>; the MCP tools map a refusal to an error result.
/// </summary>
public sealed record AgentResult<T>(T? Value, int Status, string? Error)
{
    public bool IsOk => Error is null;

    public static AgentResult<T> Ok(T value, int status = StatusCodes.Status200OK) => new(value, status, null);

    public static AgentResult<T> Refuse(int status, string error) => new(default, status, error);

    public static AgentResult<T> BadRequest(string error) => Refuse(StatusCodes.Status400BadRequest, error);

    public static AgentResult<T> NotFound(string error) => Refuse(StatusCodes.Status404NotFound, error);

    public static AgentResult<T> From(UploadLimitException ex) => Refuse(ex.StatusCode, ex.Message);

    /// <summary>Carries a refusal over to another result type.</summary>
    public AgentResult<TOther> Refusal<TOther>() =>
        IsOk ? throw new InvalidOperationException("Not a refusal.") : AgentResult<TOther>.Refuse(Status, Error!);

    /// <summary>The value as JSON (default status 200), or the <c>{ "error": ... }</c> body of the existing API.</summary>
    public IResult ToHttp(Func<T, IResult>? onOk = null) =>
        IsOk
            ? onOk?.Invoke(Value!) ?? Results.Json(Value, statusCode: Status)
            : Results.Json(new { error = Error }, statusCode: Status);
}
