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
    public void FiniteOfflineTrust_IsAnchoredToAuthorityIssueTime()
    {
        var now = DateTimeOffset.UtcNow;
        var manifest = CreateManifest(
            MagicControlOfflineTrustPolicy.For(TimeSpan.FromHours(4)),
            issuedUtc: now.AddHours(-5));
        using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var envelope = MagicControlManifestCryptography.Sign(manifest, authority);
        var state = new MagicControlManifestState(
            envelope,
            LastAuthorityContactUtc: now,
            LoadedFromDisk: false);

        Assert.False(state.AllowsOfflineUse(now));
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
    public void ManifestCache_RejectsRollbackAcrossSecurityEpochs()
    {
        using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var groupId = Guid.NewGuid();
        var current = CreateManifest(
            MagicControlOfflineTrustPolicy.Infinite,
            groupId: groupId,
            revision: 8,
            securityEpoch: Guid.NewGuid());
        var stale = CreateManifest(
            MagicControlOfflineTrustPolicy.Infinite,
            groupId: groupId,
            revision: 7,
            securityEpoch: Guid.NewGuid(),
            issuedUtc: current.IssuedUtc.AddMinutes(1));
        var cache = new MagicControlManifestCache();

        cache.Set(new MagicControlManifestState(
            MagicControlManifestCryptography.Sign(current, authority),
            current.IssuedUtc,
            LoadedFromDisk: false));
        cache.Set(new MagicControlManifestState(
            MagicControlManifestCryptography.Sign(stale, authority),
            stale.IssuedUtc,
            LoadedFromDisk: false));

        Assert.Equal(8, cache.Get(groupId)?.Manifest.Revision);
        Assert.Equal(current.SecurityEpoch, cache.Get(groupId)?.Manifest.SecurityEpoch);
    }

    [Fact]
    public async Task ManifestStore_RejectsNonPersistableSettings()
    {
        var statePath = Path.Combine(
            Path.GetTempPath(),
            "magic-control-tests",
            Guid.NewGuid().ToString("N"));

        try
        {
            var options = new MagicControlClientOptions
            {
                GroupId = Guid.NewGuid(),
                ApplicationName = "Orders",
                StatePath = statePath
            };
            var store = new FileMagicControlManifestStore(options);
            var settings = new MagicControlSettingsSnapshot(
                1,
                DateTimeOffset.UtcNow,
                [new MagicControlSettingValue("Secret", "value", PersistOffline: false)]);
            var manifest = CreateManifest(
                MagicControlOfflineTrustPolicy.Infinite,
                groupId: options.GroupId,
                settings: settings);
            using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var stored = new StoredMagicControlManifest(
                MagicControlManifestCryptography.Sign(manifest, authority),
                DateTimeOffset.UtcNow);

            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await store.SaveAsync(stored));
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
        MagicControlOfflineTrustPolicy offlineTrust,
        Guid? groupId = null,
        long revision = 1,
        Guid? securityEpoch = null,
        DateTimeOffset? issuedUtc = null,
        MagicControlSettingsSnapshot? settings = null)
    {
        var resolvedGroupId = groupId ?? Guid.NewGuid();
        var memberId = Guid.NewGuid();
        var nodeId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var now = issuedUtc ?? DateTimeOffset.UtcNow;
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
            resolvedGroupId,
            "Home",
            MagicControlGroupSecurityMode.Secured,
            securityEpoch ?? Guid.NewGuid(),
            revision,
            now,
            offlineTrust,
            [member],
            directory,
            settings ?? MagicControlSettingsSnapshot.Empty(now));
    }
}
