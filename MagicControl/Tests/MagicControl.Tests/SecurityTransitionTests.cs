using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using MagicControl.Client;
using MagicControl.Shared.Mesh;
using MagicSettings.Share;
using Microsoft.AspNetCore.Authorization;

namespace MagicControl.Tests;

public sealed class SecurityTransitionTests
{
    [Fact]
    public async Task Authorization_StartsOpenAndSwitchesToSecuredWithoutRestart()
    {
        var groupId = Guid.NewGuid();
        var cache = new MagicControlManifestCache();
        var security = new MagicControlRuntimeSecurityState();
        var handler = new MagicControlAccessHandler(cache, security);
        var requirement = new MagicControlAccessRequirement("orders.read");

        var initiallyOpen = CreateContext(requirement, new ClaimsPrincipal(new ClaimsIdentity()));
        await handler.HandleAsync(initiallyOpen);
        Assert.True(initiallyOpen.HasSucceeded);

        var secured = CreateManifest(groupId, MagicControlGroupSecurityMode.Secured);
        await security.ApplyValidatedManifestAsync(secured);
        cache.Set(new MagicControlManifestState(
            secured,
            DateTimeOffset.UtcNow,
            LoadedFromDisk: false));

        var anonymousAfterApproval = CreateContext(
            requirement,
            new ClaimsPrincipal(new ClaimsIdentity()));
        await handler.HandleAsync(anonymousAfterApproval);
        Assert.False(anonymousAfterApproval.HasSucceeded);

        var approvedIdentity = new ClaimsIdentity(
            [
                new Claim(MagicControlMeshProtocol.GroupIdClaim, groupId.ToString("D")),
                new Claim(MagicControlMeshProtocol.CapabilityClaim, "orders.read")
            ],
            MagicControlMeshProtocol.NodeAuthenticationScheme);
        var approved = CreateContext(requirement, new ClaimsPrincipal(approvedIdentity));
        await handler.HandleAsync(approved);
        Assert.True(approved.HasSucceeded);
    }

    [Fact]
    public async Task SecuredLatch_SurvivesRestartAndCorruptOrdinaryStateUntilValidatedOpenManifest()
    {
        var statePath = Path.Combine(
            Path.GetTempPath(),
            "magic-control-security-latch",
            Guid.NewGuid().ToString("N"));
        var options = new MagicControlClientOptions
        {
            GroupId = Guid.NewGuid(),
            ApplicationName = "Orders",
            StatePath = statePath,
            EnableAutomaticDiscovery = false,
            EnableDirectPeerDiscovery = false
        };
        options.Validate();

        try
        {
            var store = new FileMagicControlSecurityLatchStore(options);
            var runtime = new MagicControlRuntimeSecurityState(store);
            var secured = CreateManifest(
                options.GroupId,
                MagicControlGroupSecurityMode.Secured);

            await runtime.ApplyValidatedManifestAsync(secured);
            Assert.True(runtime.RequiresAuthorization);
            Assert.True(store.IsLatched);

            // The latch is defined by file presence, not parseable contents. A truncated marker
            // therefore remains fail-closed rather than looking like a fresh unmanaged install.
            var latchPath = Path.Combine(statePath, options.SecurityLatchFileName);
            await File.WriteAllTextAsync(latchPath, string.Empty);
            var restarted = new MagicControlRuntimeSecurityState(
                new FileMagicControlSecurityLatchStore(options));
            Assert.True(restarted.RequiresAuthorization);

            var handler = new MagicControlAccessHandler(
                new MagicControlManifestCache(),
                restarted);
            var denied = CreateContext(
                new MagicControlAccessRequirement(null),
                new ClaimsPrincipal(new ClaimsIdentity()));
            await handler.HandleAsync(denied);
            Assert.False(denied.HasSucceeded);

            var open = CreateManifest(
                options.GroupId,
                MagicControlGroupSecurityMode.Open);
            await restarted.ApplyValidatedManifestAsync(open);

            Assert.False(restarted.RequiresAuthorization);
            Assert.False(File.Exists(latchPath));

            var opened = CreateContext(
                new MagicControlAccessRequirement(null),
                new ClaimsPrincipal(new ClaimsIdentity()));
            await handler.HandleAsync(opened);
            Assert.True(opened.HasSucceeded);
        }
        finally
        {
            if (Directory.Exists(statePath))
            {
                Directory.Delete(statePath, recursive: true);
            }
        }
    }

    [Fact]
    public void ServiceResolver_DoesNotReturnIdentityOnlyPeersAfterSecuredLatch()
    {
        var options = new MagicControlClientOptions
        {
            GroupId = Guid.NewGuid(),
            ApplicationName = "Consumer",
            EnableAutomaticDiscovery = false,
            EnableDirectPeerDiscovery = false
        };
        options.Validate();

        var peers = new MagicControlPeerDirectory(options);
        Assert.True(peers.Accept(
            CreateSignedAdvertisement(options.GroupId, "Orders"),
            DateTimeOffset.UtcNow));
        var resolver = new MagicControlServiceResolver(
            options,
            new MagicControlManifestCache(),
            peers,
            new MagicControlRuntimeSecurityState(requiresAuthorization: true));

        Assert.Null(resolver.Resolve("Orders"));
    }

    private static AuthorizationHandlerContext CreateContext(
        MagicControlAccessRequirement requirement,
        ClaimsPrincipal principal)
        => new([requirement], principal, resource: null);

    private static SignedMagicControlGroupManifest CreateManifest(
        Guid groupId,
        MagicControlGroupSecurityMode mode)
    {
        var now = DateTimeOffset.UtcNow;
        var manifest = new MagicControlGroupManifest(
            groupId,
            "Home",
            mode,
            Guid.NewGuid(),
            1,
            now,
            MagicControlOfflineTrustPolicy.Infinite,
            [],
            [],
            MagicControlSettingsSnapshot.Empty(now));
        using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return MagicControlManifestCryptography.Sign(manifest, authority);
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
