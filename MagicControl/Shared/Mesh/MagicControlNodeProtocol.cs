namespace MagicControl.Shared.Mesh;

public static class MagicControlNodeProtocol
{
    public const string NodeSyncAudience = "MagicControl.Node.Sync";
    public const string NodeSecretAudience = "MagicControl.Node.Secret";

    public const string DiscoveryMulticastAddress = "239.255.77.77";
    public const int DiscoveryPort = 45873;
    public const int DiscoveryProtocolVersion = 1;

    public const string PeerDiscoveryAudience = "MagicControl.Peer.Discovery";
    public const string PeerDiscoveryMulticastAddress = "239.255.77.78";
    public const int PeerDiscoveryPort = 45874;
    public const int PeerDiscoveryProtocolVersion = 1;
}
