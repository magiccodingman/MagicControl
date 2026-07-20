using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using MagicControl.Shared.Mesh;
using MagicSettings.Share;

namespace MagicControl.Client;

internal sealed record MagicControlPeerAdvertisementValidation(
    bool IsValid,
    string? Error)
{
    public static MagicControlPeerAdvertisementValidation Valid { get; } = new(true, null);
    public static MagicControlPeerAdvertisementValidation Invalid(string error) => new(false, error);
}

internal static class MagicControlPeerAdvertisementSecurity
{
    private const string ProofVersion = "MAGICSETTINGS-PROOF-V1";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    public static byte[] Serialize(MagicControlPeerAdvertisement advertisement)
        => JsonSerializer.SerializeToUtf8Bytes(advertisement, JsonOptions);

    public static string ComputeBodySha256(MagicControlPeerAdvertisement advertisement)
        => Convert.ToHexString(SHA256.HashData(Serialize(advertisement))).ToLowerInvariant();

    public static Uri Target(MagicControlPeerAdvertisement advertisement)
        => new(
            $"https://magiccontrol.local/groups/{advertisement.GroupId:D}/peers/{advertisement.Identity.NodeId:D}/{advertisement.Identity.CredentialId:D}/advertisement",
            UriKind.Absolute);

    public static MagicControlPeerAdvertisementValidation Validate(
        SignedMagicControlPeerAdvertisement envelope,
        MagicControlClientOptions options,
        DateTimeOffset nowUtc,
        bool enforceCurrentLifetime)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        var advertisement = envelope.Advertisement;
        var proof = envelope.Proof;

        if (advertisement.ProtocolVersion != MagicControlNodeProtocol.PeerDiscoveryProtocolVersion)
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer advertisement protocol version is unsupported.");
        }

        if (advertisement.GroupId != options.GroupId)
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer advertisement belongs to another group.");
        }

        if (string.IsNullOrWhiteSpace(advertisement.ApplicationName)
            || string.IsNullOrWhiteSpace(advertisement.DisplayName)
            || advertisement.Endpoints.Count == 0)
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer advertisement is missing required application metadata or endpoints.");
        }

        if (advertisement.TimeToLiveSeconds is < 5 or > 300)
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer advertisement TTL is outside the allowed range.");
        }

        if (advertisement.Endpoints.Any(endpoint =>
                endpoint.Uri is null
                || !endpoint.Uri.IsAbsoluteUri
                || !options.IsEndpointAllowed(endpoint.Uri)))
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer advertisement contains an endpoint that is not allowed by this client.");
        }

        if (proof.NodeId != advertisement.Identity.NodeId
            || proof.CredentialId != advertisement.Identity.CredentialId)
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer proof does not match the advertised identity.");
        }

        if (!string.Equals(proof.Version, ProofVersion, StringComparison.Ordinal)
            || !string.Equals(proof.Audience, MagicControlNodeProtocol.PeerDiscoveryAudience, StringComparison.Ordinal)
            || !string.Equals(proof.Method, "ANNOUNCE", StringComparison.OrdinalIgnoreCase)
            || !string.Equals(proof.Target, Target(advertisement).AbsoluteUri, StringComparison.Ordinal)
            || !string.Equals(proof.BodySha256, ComputeBodySha256(advertisement), StringComparison.OrdinalIgnoreCase)
            || proof.ExpiresUtc <= proof.IssuedUtc
            || proof.ExpiresUtc - proof.IssuedUtc > TimeSpan.FromMinutes(5)
            || string.IsNullOrWhiteSpace(proof.Nonce))
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer advertisement proof is structurally invalid.");
        }

        if (advertisement.IssuedUtc < proof.IssuedUtc - TimeSpan.FromSeconds(5)
            || advertisement.IssuedUtc > proof.ExpiresUtc)
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer advertisement timestamp is not bound to the proof lifetime.");
        }

        if (proof.IssuedUtc - TimeSpan.FromSeconds(30) > nowUtc)
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer advertisement proof was issued too far in the future.");
        }

        if (enforceCurrentLifetime
            && (proof.ExpiresUtc + TimeSpan.FromSeconds(30) < nowUtc
                || advertisement.IssuedUtc.AddSeconds(advertisement.TimeToLiveSeconds) < nowUtc))
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer advertisement has expired.");
        }

        string expectedFingerprint;
        try
        {
            expectedFingerprint = Convert.ToHexString(
                    SHA256.HashData(Convert.FromBase64String(advertisement.Identity.PublicKey)))
                .ToLowerInvariant();
        }
        catch (FormatException)
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer public key is malformed.");
        }

        if (!string.Equals(
                expectedFingerprint,
                advertisement.Identity.Fingerprint,
                StringComparison.OrdinalIgnoreCase))
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer fingerprint does not match its public key.");
        }

        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(
                Convert.FromBase64String(advertisement.Identity.PublicKey),
                out _);
            if (!key.VerifyData(
                    Encoding.UTF8.GetBytes(Canonicalize(proof)),
                    Convert.FromBase64String(proof.Signature),
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                return MagicControlPeerAdvertisementValidation.Invalid("The peer advertisement signature is invalid.");
            }
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            return MagicControlPeerAdvertisementValidation.Invalid("The peer advertisement key or signature is malformed.");
        }

        return MagicControlPeerAdvertisementValidation.Valid;
    }

    private static string Canonicalize(MagicAuthenticationProof proof)
        => string.Join(
            '\n',
            proof.Version,
            proof.NodeId.ToString("D"),
            proof.CredentialId.ToString("D"),
            proof.Audience,
            proof.Method.ToUpperInvariant(),
            proof.Target,
            proof.BodySha256.ToLowerInvariant(),
            proof.IssuedUtc.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture),
            proof.ExpiresUtc.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture),
            proof.Nonce);
}
