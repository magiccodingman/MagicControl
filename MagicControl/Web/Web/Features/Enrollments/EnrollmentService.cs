using System.Text.Json;
using MagicControl.Shared.Enrollments;
using MagicControl.Web.Data;
using MagicSettings.Share;
using Microsoft.EntityFrameworkCore;

namespace MagicControl.Web.Features.Enrollments;

public sealed record ManagedCredentialSummary(
    Guid NodeId,
    Guid CredentialId,
    string Fingerprint,
    MagicCredentialStatus Status,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc);

public sealed record ManagedInstanceDetail(
    ManagedInstanceSummary Instance,
    IReadOnlyList<ManagedCredentialSummary> Credentials);

public sealed partial class EnrollmentService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly IDbContextFactory<MagicControlDbContext> dbFactory;

    public EnrollmentService(IDbContextFactory<MagicControlDbContext> dbFactory)
        => this.dbFactory = dbFactory;
}
