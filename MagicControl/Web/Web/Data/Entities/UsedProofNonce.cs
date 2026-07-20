namespace MagicControl.Web.Data.Entities;

public sealed class UsedProofNonce
{
    public Guid CredentialId { get; set; }
    public required string Nonce { get; set; }
    public DateTimeOffset ExpiresUtc { get; set; }
    public DateTimeOffset UsedUtc { get; set; }
}
