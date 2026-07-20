using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using MagicControl.Shared.Enrollments;
using MagicControl.Shared.Security;
using MagicControl.Web.Configuration;
using MagicControl.Web.Features.Enrollments;
using MagicSettings.Server;
using MagicSettings.Share;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace MagicControl.Web.Controllers;

public sealed record ReviewEnrollmentApiRequest(bool Approve, string? Reason);

[ApiController]
[Route("api/v1/enrollments")]
public sealed class EnrollmentsController(
    MagicNodeProofVerifier proofVerifier,
    EnrollmentService enrollments,
    IOptionsMonitor<MagicControlSettings> settings) : ControllerBase
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [HttpPost]
    [AllowAnonymous]
    [Consumes("application/json")]
    public async Task<IActionResult> Submit(CancellationToken cancellationToken)
    {
        if (!settings.CurrentValue.Enrollment.AllowNewRequests)
        {
            return StatusCode(
                StatusCodes.Status503ServiceUnavailable,
                new { error = "New enrollment requests are disabled." });
        }

        var maximumBytes = Math.Max(16_384, settings.CurrentValue.Enrollment.MaximumRequestBytes);
        if (Request.ContentLength is > 0 && Request.ContentLength > maximumBytes)
        {
            return StatusCode(StatusCodes.Status413PayloadTooLarge);
        }

        byte[] body;
        await using (var buffer = new MemoryStream())
        {
            await Request.Body.CopyToAsync(buffer, cancellationToken);
            if (buffer.Length > maximumBytes)
            {
                return StatusCode(StatusCodes.Status413PayloadTooLarge);
            }

            body = buffer.ToArray();
        }

        EnrollmentSubmission? submission;
        try
        {
            submission = JsonSerializer.Deserialize<EnrollmentSubmission>(body, JsonOptions);
        }
        catch (JsonException)
        {
            return BadRequest(new { error = "The enrollment body is not valid JSON." });
        }

        if (submission is null)
        {
            return BadRequest(new { error = "The enrollment body is required." });
        }

        if (!Request.Headers.TryGetValue("Authorization", out var authorization))
        {
            return Unauthorized();
        }

        const string prefix = "MagicNode ";
        var header = authorization.ToString();
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return Unauthorized();
        }

        MagicAuthenticationProof proof;
        try
        {
            proof = MagicNodeProofCodec.Decode(header[prefix.Length..].Trim());
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            return Unauthorized();
        }

        var uri = new Uri(
            $"{Request.Scheme}://{Request.Host}{Request.PathBase}{Request.Path}{Request.QueryString}");
        var bodyHash = Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();

        var verification = await proofVerifier.VerifyEnrollmentAsync(
            submission.Identity,
            new MagicProofVerificationRequest(
                proof,
                MagicControlSecurity.EnrollmentAudience,
                Request.Method,
                uri,
                bodyHash,
                DateTimeOffset.UtcNow),
            cancellationToken);

        if (!verification.IsValid)
        {
            return Unauthorized();
        }

        try
        {
            var receipt = await enrollments.SubmitVerifiedAsync(submission, cancellationToken);
            return receipt.Status == EnrollmentRequestStatus.Pending
                ? Accepted(receipt)
                : Ok(receipt);
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { error = exception.Message });
        }
        catch (InvalidOperationException exception)
        {
            return Conflict(new { error = exception.Message });
        }
    }

    [HttpGet]
    [RequireMagicControlRole(MagicControlRoles.EnrollmentAdministrator)]
    public async Task<IActionResult> Get(
        [FromQuery] EnrollmentRequestStatus? status,
        CancellationToken cancellationToken)
        => Ok(await enrollments.GetRequestsAsync(status, cancellationToken));

    [HttpPost("{id:guid}/review")]
    [ValidateAntiForgeryToken]
    [RequireMagicControlRole(MagicControlRoles.EnrollmentAdministrator)]
    public async Task<IActionResult> Review(
        Guid id,
        ReviewEnrollmentApiRequest request,
        CancellationToken cancellationToken)
    {
        var reviewer = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var receipt = await enrollments.ReviewAsync(
            id,
            request.Approve,
            request.Reason,
            reviewer,
            cancellationToken);
        return Ok(receipt);
    }
}
