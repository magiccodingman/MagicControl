using MagicSettings.Share;

namespace MagicControl.Web.Data.Entities;

public sealed class InstanceCredential
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid NodeId { get; set; }
    public Guid CredentialId { get; set; }

    public required string PublicKey { get; set; }
    public required string Fingerprint { get; set; }
    public required string SignatureAlgorithm { get; set; }
    public MagicCredentialStatus Status { get; set; }

    public Guid? ManagedInstanceId { get; set; }
    public ManagedInstance? ManagedInstance { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset UpdatedUtc { get; set; }
    public DateTimeOffset? RetiringUtc { get; set; }
    public DateTimeOffset? RevokedUtc { get; set; }
}
