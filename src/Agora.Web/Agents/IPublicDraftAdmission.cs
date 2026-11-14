namespace Agora.Web.Agents;

/// <param name="OwnerUserId">The owner of the upload link the draft belongs to.</param>
/// <param name="DraftId">The open anonymous draft the file goes into.</param>
public sealed record PublicTicketAdmission(Guid OwnerUserId, string DraftId);

/// <summary>
/// Admission of an anonymous (upload link) one-time upload URL at the moment it is used: the code still resolves to
/// its owner, the owner still accepts agent uploads, the draft is still open. Implemented by the upload-link service;
/// until one is registered, public tickets are answered 404.
/// </summary>
public interface IPublicDraftAdmission
{
    Task<AgentResult<PublicTicketAdmission>> AdmitAsync(AgentTicketStore.Ticket ticket, HttpContext context, CancellationToken ct);
}
