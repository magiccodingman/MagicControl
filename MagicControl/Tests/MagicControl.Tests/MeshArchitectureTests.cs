using System.Security.Cryptography;
using MagicControl.Client;
using MagicControl.Shared.Enrollments;
using MagicControl.Shared.Mesh;
using MagicSettings.Share;

namespace MagicControl.Tests;

public sealed class MeshArchitectureTests
{
    [Fact]
    public void OfflineTrust_IsInfiniteByDefault()
    {
        var now = DateTimeOffset.UtcNow;

        Assert.True(MagicControlOfflineTrustPolicy.Infinite.IsInfinite);
        Assert.True(MagicControlOfflineTrustPolicy.Infinite.AllowsOfflineUse(
            now.AddYears(-20),
            now));
    }

    [Fact]
    public void OfflineTrust_CanBeLimitedPerGroup()
    {
        var policy = MagicControlOfflineTrustPolicy.For(TimeSpan.FromHours(4));
        var contact = DateTimeOffset.UtcNow;

        Assert.True(policy.AllowsOfflineUse(contact, contact.AddHours(3)));
        Assert.False(policy.AllowsOfflineUse(contact, contact.AddHours(5)));
    }

    [Fact]
    public void SignedManifest_DetectsTampering()
    {
        using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifest = CreateManifest(MagicControlOfflineTrustPolicy.Infinite);
        var signed = MagicControlManifestCryptography.Sign(manifest, authority);

        Assert.True(MagicControlManifestCryptography.Verify(signed));

        var tampered = signed with
        {
            Manifest = signed.Manifest with { Revision = signed.Manifest.Revision + 1 }
        };
        Assert.False(MagicControlManifestCryptography.Verify(tampered));
    }

    [Fact]
    public void DirectoryResolution_ReturnsEveryMatchingInstance()
    {
        var manifest = CreateManifest(MagicControlOfflineTrustPolicy.Infinite);
        using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var envelope = MagicControlManifestCryptography.Sign(manifest, authority);
        var cache = new MagicControlManifestCache();
        cache.Set(new MagicControlManifestState(
            envelope,
            DateTimeOffset.UtcNow.AddYears(-10),
            LoadedFromDisk: true));
        var authorization = new MagicControlAuthorizationService(cache);

        var entries = authorization.ResolveAll(manifest.GroupId, "Orders");

        Assert.Equal(3, entries.Count);
        Assert.Equal(
            manifest.Directory.Select(entry => entry.ManagedInstanceId).OrderBy(id => id),
            entries.Select(entry => entry.ManagedInstanceId).OrderBy(id => id));
    }

    [Fact]
    public void CachedAuthorization_DoesNotRequireAControlPlaneRequest()
    {
        var manifest = CreateManifest(MagicControlOfflineTrustPolicy.Infinite);
        using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var envelope = MagicControlManifestCryptography.Sign(manifest, authority);
        var cache = new MagicControlManifestCache();
        cache.Set(new MagicControlManifestState(
            envelope,
            DateTimeOffset.UtcNow.AddDays(-30),
            LoadedFromDisk: true));
        var authorization = new MagicControlAuthorizationService(cache);
        var member = manifest.Members.Single();

        var decision = authorization.AuthorizeMember(
            manifest.GroupId,
            member.NodeId,
            member.CredentialId,
            "orders.read");

        Assert.True(decision.Allowed);
        Assert.Equal(member.ManagedInstanceId, decision.Member?.ManagedInstanceId);
    }

    private static MagicControlGroupManifest CreateManifest(
        MagicControlOfflineTrustPolicy offlineTrust)
    {
        var groupId = Guid.NewGuid();
        var memberId = Guid.NewGuid();
        var nodeId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var member = new MagicControlMember(
            memberId,
            EnrollmentKind.ApplicationInstance,
            "Orders primary",
            "Orders",
            "primary",
            "api",
            "home",
            nodeId,
            credentialId,
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(91)),
            MagicCredentialStatus.Approved,
            [],
            ["orders.read"]);

        var directory = Enumerable.Range(1, 3)
            .Select(index => new MagicControlDirectoryEntry(
                Guid.NewGuid(),
                "Orders",
                $"orders-{index}",
                "api",
                "home",
                [new MagicControlServiceEndpoint(
                    new Uri($"https://127.0.0.1:{7000 + index}"),
                    Priority: index,
                    IsLoopback: true)],
                index,
                now,
                null))
            .ToArray();

        return new MagicControlGroupManifest(
            groupId,
            "Home",
            MagicControlGroupSecurityMode.Secured,
            Guid.NewGuid(),
            1,
            now,
            offlineTrust,
            [member],
            directory,
            MagicControlSettingsSnapshot.Empty(now));
    }
}
