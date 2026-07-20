namespace MagicControl.Client;

public enum MagicControlStartupMode
{
    CachedFirst = 1,
    PreferMesh = 2,
    RequireMesh = 3
}

public sealed class MagicControlClientOptions
{
    public Guid GroupId { get; set; }
    public string ApplicationName { get; set; } = string.Empty;
    public string StatePath { get; set; } = "state/magic-control";
    public string ManifestFileName { get; set; } = "group-manifest.protected";
    public MagicControlStartupMode StartupMode { get; set; } = MagicControlStartupMode.CachedFirst;
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromSeconds(30);
    public TimeSpan MeshRequestTimeout { get; set; } = TimeSpan.FromSeconds(5);
    public List<Uri> MeshEndpoints { get; } = [];

    /// <summary>
    /// Pins the MagicControl Web authority public key used to sign secured group manifests.
    /// Enrollment will populate this automatically in a later protocol slice.
    /// </summary>
    public string? TrustedAuthorityPublicKey { get; set; }

    /// <summary>
    /// Allows the first valid secured manifest to establish the authority pin locally.
    /// This is intentionally disabled by default; open groups do not require a pin.
    /// </summary>
    public bool AllowAuthorityTrustOnFirstUse { get; set; }

    public void AddMeshEndpoint(string endpoint)
        => MeshEndpoints.Add(new Uri(endpoint, UriKind.Absolute));

    internal void Validate()
    {
        if (GroupId == Guid.Empty)
        {
            throw new InvalidOperationException("MagicControl client GroupId is required.");
        }

        if (string.IsNullOrWhiteSpace(ApplicationName))
        {
            throw new InvalidOperationException("MagicControl client ApplicationName is required.");
        }

        if (RefreshInterval < TimeSpan.FromSeconds(1))
        {
            throw new InvalidOperationException("MagicControl client refresh interval must be at least one second.");
        }

        if (MeshRequestTimeout <= TimeSpan.Zero)
        {
            throw new InvalidOperationException("MagicControl client Mesh request timeout must be positive.");
        }
    }
}
