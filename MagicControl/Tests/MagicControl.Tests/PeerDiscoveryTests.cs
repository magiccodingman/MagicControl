using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using MagicControl.Client;
using MagicControl.Shared.Enrollments;
using MagicControl.Shared.Mesh;
using MagicSettings.Share;

namespace MagicControl.Tests;

public sealed class PeerDiscoveryTests
{
    [Fact]
    public void PeerAdvertisement_ValidatesAndRejectsTampering()
    {
        var options = CreateOptions();
        var signed = CreateSignedAdvertisement(options.GroupId, "Orders");

        var valid = MagicControlPeerAdvertisementSecurity.Validate(
            signed,
            options,
            DateTimeOffset.UtcNow,
            enforceCurrentLifetime: true);
        var tampered = signed with
        {
            Advertisement = signed.Advertisement with
            {
                ApplicationName = "Inventory"
            }
        };
        var invalid = MagicControlPeerAdvertisementSecurity.Validate(
            tampered,
            options,
            DateTimeOffset.UtcNow,
            enforceCurrentLifetime: true);

        Assert.True(valid.IsValid, valid.Error);
        Assert.False(invalid.IsValid);
    }

    [Fact]
    public void ServiceResolver_ReturnsIdentityVerifiedPeerWithoutManifest()
    {
        var options = CreateOptions();
        var cache = new MagicControlManifestCache();
        var peers = new MagicControlPeerDirectory(options);
        var signed = CreateSignedAdvertisement(options.GroupId, "Orders");
        Assert.True(peers.Accept(signed, DateTimeOffset.UtcNow));
        var resolver = new MagicControlServiceResolver(options, cache, peers);

        var result = resolver.Resolve("Orders");

        Assert.NotNull(result);
        Assert.Equal(MagicControlPeerTrustLevel.IdentityVerified, result.TrustLevel);
        Assert.Equal(MagicControlServiceDiscoverySource.DirectPeerLan, result.Source);
        Assert.Equal("192.168.10.25", result.Endpoint.Uri.Host);
        Assert.False(result.IsAuthorityApproved);
    }

    [Fact]
    public void ServiceResolver_SecuredManifestRejectsUnapprovedDirectPeer()
    {
        var options = CreateOptions();
        var cache = CreateManifestCache(options.GroupId, []);
        var peers = new MagicControlPeerDirectory(options);
        var signed = CreateSignedAdvertisement(options.GroupId, "Orders");
        Assert.True(peers.Accept(signed, DateTimeOffset.UtcNow));
        var resolver = new MagicControlServiceResolver(options, cache, peers);

        var result = resolver.Resolve("Orders");

        Assert.Null(result);
    }

    [Fact]
    public void ServiceResolver_SecuredManifestUpgradesExactApprovedPeer()
    {
        var options = CreateOptions();
        var signed = CreateSignedAdvertisement(options.GroupId, "Orders");
        var advertisement = signed.Advertisement;
        var member = new MagicControlMember(
            Guid.NewGuid(),
            EnrollmentKind.ApplicationInstance,
            advertisement.DisplayName,
            advertisement.ApplicationName,
            advertisement.InstanceName,
            advertisement.InstanceRole,
            advertisement.SiteName,
            advertisement.Identity.NodeId,
            advertisement.Identity.CredentialId,
            advertisement.Identity.PublicKey,
            MagicCredentialStatus.Approved,
            [],
            ["orders.read"]);
        var cache = CreateManifestCache(options.GroupId, [member]);
        var peers = new MagicControlPeerDirectory(options);
        Assert.True(peers.Accept(signed, DateTimeOffset.UtcNow));
        var resolver = new MagicControlServiceResolver(options, cache, peers);

        var result = resolver.Resolve("Orders");

        Assert.NotNull(result);
        Assert.Equal(MagicControlPeerTrustLevel.AuthorityApproved, result.TrustLevel);
        Assert.Equal(MagicControlServiceDiscoverySource.DirectPeerLan, result.Source);
        Assert.True(result.IsAuthorityApproved);
        Assert.Equal(member.ManagedInstanceId, result.Instance.ManagedInstanceId);
    }

    [Fact]
    public async Task PeerDirectoryStore_EncryptsAndReloadsVerifiedObservations()
    {
        var statePath = Path.Combine(
            Path.GetTempPath(),
            "magic-control-peer-cache",
            Guid.NewGuid().ToString("N"));
        var options = CreateOptions() withStatePath(statePath);
        var signed = CreateSignedAdvertisement(options.GroupId, "Orders");
        var observation = new MagicControlPeerObservation(
            signed,
            DateTimeOffset.UtcNow,
            LoadedFromDisk: false);

        try
        {
            using (var store = new FileMagicControlPeerDirectoryStore(options))
            {
                await store.SaveAsync([observation]);
            }

            var path = Path.Combine(statePath, options.PeerDirectoryFileName);
            var bytes = await File.ReadAllBytesAsync(path);
            Assert.DoesNotContain(
                Encoding.UTF8.GetBytes("192.168.10.25"),
                bytes);

            using var reopened = new FileMagicControlPeerDirectoryStore(options);
            var loaded = await reopened.LoadAsync();
            Assert.Single(loaded);
            var validation = MagicControlPeerAdvertisementSecurity.Validate(
                loaded[0].Envelope,
                options,
                DateTimeOffset.UtcNow,
                enforceCurrentLifetime: false);
            Assert.True(validation.IsValid, validation.Error);
        }
        finally
        {
            if (Directory.Exists(statePath))
            {
                Directory.Delete(statePath, recursive: true);
            }
        }
    }

    private static MagicControlClientOptions CreateOptions()
    {
        var options = new MagicControlClientOptions
        {
            GroupId = Guid.NewGuid(),
            ApplicationName = "Consumer",
            EnableAutomaticDiscovery = false,
            EnableDirectPeerDiscovery = false
        };
        options.Validate();
        return options;
    }

    private static MagicControlClientOptions withStatePath(
        this MagicControlClientOptions options,
        string statePath)
    {
        options.StatePath = statePath;
        return options;
    }

    private static MagicControlManifestCache CreateManifestCache(
        Guid groupId,
        IReadOnlyList<MagicControlMember> members)
    {
        var now = DateTimeOffset.UtcNow;
        var manifest = new MagicControlGroupManifest(
            groupId,
            "Home",
            MagicControlGroupSecurityMode.Secured,
            Guid.NewGuid(),
            1,
            now,
            MagicControlOfflineTrustPolicy.Infinite,
            members,
            [],
            MagicControlSettingsSnapshot.Empty(now));
        using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var cache = new MagicControlManifestCache();
        cache.Set(new MagicControlManifestState(
            MagicControlManifestCryptography.Sign(manifest, authority),
            now,
            LoadedFromDisk: false));
        return cache;
    }

    private static SignedMagicControlPeerAdvertisement CreateSignedAdvertisement(
        Guid groupId,
        string applicationName)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        var now = DateTimeOffset.UtcNow;
        var identity = new MagicNodeIdentityDescriptor(
            Guid.NewGuid(),
            Guid.NewGuid(),
            MagicCredentialKind.EcdsaP256,
            "ECDSA_P256_SHA256_P1363",
            publicKey,
            Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(publicKey))).ToLowerInvariant(),
            now);
        var advertisement = new MagicControlPeerAdvertisement(
            MagicControlNodeProtocol.PeerDiscoveryProtocolVersion,
            groupId,
            applicationName,
            $"{applicationName} primary",
            "orders-1",
            "api",
            "home",
            "1.0.0",
            identity,
            [new MagicControlServiceEndpointAnnouncement(
                new Uri("https://192.168.10.25:7443"),
                Priority: 10,
                IsLan: true)],
            1,
            now,
            20);
        var unsigned = new MagicAuthenticationProof(
            "MAGICSETTINGS-PROOF-V1",
            identity.NodeId,
            identity.CredentialId,
            MagicControlNodeProtocol.PeerDiscoveryAudience,
            "ANNOUNCE",
            MagicControlPeerAdvertisementSecurity.Target(advertisement).AbsoluteUri,
            MagicControlPeerAdvertisementSecurity.ComputeBodySha256(advertisement),
            now,
            now.AddMinutes(1),
            "test-nonce",
            string.Empty);
        var signature = key.SignData(
            Encoding.UTF8.GetBytes(Canonicalize(unsigned)),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new SignedMagicControlPeerAdvertisement(
            advertisement,
            unsigned with { Signature = Convert.ToBase64String(signature) });
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
