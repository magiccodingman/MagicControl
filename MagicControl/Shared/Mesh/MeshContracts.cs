using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using MagicControl.Shared.Enrollments;
using MagicSettings.Share;

namespace MagicControl.Shared.Mesh;

public enum MagicControlGroupSecurityMode
{
    Open = 1,
    Secured = 2
}

public sealed record MagicControlOfflineTrustPolicy
{
    public long? MaximumOfflineSeconds { get; init; }

    [JsonIgnore]
    public bool IsInfinite => MaximumOfflineSeconds is null;

    public static MagicControlOfflineTrustPolicy Infinite { get; } = new();

    public static MagicControlOfflineTrustPolicy For(TimeSpan duration)
    {
        if (duration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(duration), "Offline trust must be greater than zero.");
        }

        return new MagicControlOfflineTrustPolicy
        {
            MaximumOfflineSeconds = checked((long)Math.Ceiling(duration.TotalSeconds))
        };
    }

    public bool AllowsOfflineUse(DateTimeOffset lastAuthorityContactUtc, DateTimeOffset nowUtc)
        => MaximumOfflineSeconds is null
           || nowUtc <= lastAuthorityContactUtc.AddSeconds(MaximumOfflineSeconds.Value);
}

public sealed record MagicControlServiceEndpoint(
    Uri Uri,
    int Priority = 100,
    bool IsLoopback = false,
    bool IsLan = false,
    string Transport = "https");

public sealed record MagicControlMember(
    Guid ManagedInstanceId,
    EnrollmentKind Kind,
    string DisplayName,
    string? ApplicationName,
    string? InstanceName,
    string? InstanceRole,
    string? SiteName,
    Guid NodeId,
    Guid CredentialId,
    string PublicKey,
    MagicCredentialStatus CredentialStatus,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Capabilities);

public sealed record MagicControlDirectoryEntry(
    Guid ManagedInstanceId,
    string? ApplicationName,
    string? InstanceName,
    string? InstanceRole,
    string? SiteName,
    IReadOnlyList<MagicControlServiceEndpoint> Endpoints,
    long Sequence,
    DateTimeOffset ObservedUtc,
    DateTimeOffset? ExpiresUtc);

public sealed record MagicControlSettingValue(
    string Key,
    string? Value,
    bool PersistOffline = true);

public sealed record MagicControlSettingsSnapshot(
    long Revision,
    DateTimeOffset IssuedUtc,
    IReadOnlyList<MagicControlSettingValue> Values)
{
    public static MagicControlSettingsSnapshot Empty(DateTimeOffset issuedUtc)
        => new(0, issuedUtc, []);
}

public sealed record MagicControlGroupManifest(
    Guid GroupId,
    string GroupName,
    MagicControlGroupSecurityMode SecurityMode,
    Guid SecurityEpoch,
    long Revision,
    DateTimeOffset IssuedUtc,
    MagicControlOfflineTrustPolicy OfflineTrust,
    IReadOnlyList<MagicControlMember> Members,
    IReadOnlyList<MagicControlDirectoryEntry> Directory,
    MagicControlSettingsSnapshot Settings);

public sealed record SignedMagicControlGroupManifest(
    string AuthorityKeyId,
    string AuthorityPublicKey,
    MagicControlGroupManifest Manifest,
    string Signature);

public static class MagicControlManifestCryptography
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    public static SignedMagicControlGroupManifest Sign(
        MagicControlGroupManifest manifest,
        ECDsa authorityKey)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(authorityKey);

        var publicKeyBytes = authorityKey.ExportSubjectPublicKeyInfo();
        var publicKey = Convert.ToBase64String(publicKeyBytes);
        var signature = authorityKey.SignData(
            Serialize(manifest),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return new SignedMagicControlGroupManifest(
            ComputeKeyId(publicKeyBytes),
            publicKey,
            manifest,
            Convert.ToBase64String(signature));
    }

    public static bool Verify(SignedMagicControlGroupManifest envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        try
        {
            var publicKeyBytes = Convert.FromBase64String(envelope.AuthorityPublicKey);
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(ComputeKeyId(publicKeyBytes)),
                    Encoding.ASCII.GetBytes(envelope.AuthorityKeyId.ToLowerInvariant())))
            {
                return false;
            }

            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            return key.VerifyData(
                Serialize(envelope.Manifest),
                Convert.FromBase64String(envelope.Signature),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            return false;
        }
    }

    public static bool PublicKeysMatch(string expectedPublicKey, string actualPublicKey)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(expectedPublicKey),
                Convert.FromBase64String(actualPublicKey));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static byte[] Serialize(MagicControlGroupManifest manifest)
        => JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);

    public static string ComputeKeyId(string publicKey)
        => ComputeKeyId(Convert.FromBase64String(publicKey));

    private static string ComputeKeyId(byte[] publicKey)
        => Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant();
}

public static class MagicControlMeshProtocol
{
    public const string MeshControlPlaneAudience = "MagicControl.Mesh.ControlPlane";
    public const string MeshPeerAudience = "MagicControl.Mesh.Peer";
    public const string NodeAuthenticationScheme = "MagicControl.Node";
    public const string CapabilityPolicyPrefix = "MagicControl.Capability:";

    public const string NodeIdClaim = "magiccontrol:node_id";
    public const string CredentialIdClaim = "magiccontrol:credential_id";
    public const string GroupIdClaim = "magiccontrol:group_id";
    public const string CapabilityClaim = "magiccontrol:capability";
}
