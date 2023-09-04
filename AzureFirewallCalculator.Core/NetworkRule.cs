namespace AzureFirewallCalculator.Core;

public record class NetworkRule
{
    public string Name { get;}

    public RuleIpRange[] SourceIps { get; }

    public RuleIpRange[] DestinationIps { get; }

    public RulePortRange[] DestinationPorts { get; }

    public NetworkProtocols NetworkProtocols { get; }

    public NetworkRule(string name, RuleIpRange[] sourceIps, RuleIpRange[] destinationIps, RulePortRange[] destinationPorts, NetworkProtocols networkProtocols)
    {
        Name = name;
        SourceIps = sourceIps;
        DestinationIps = destinationIps;
        DestinationPorts = destinationPorts;
        NetworkProtocols = networkProtocols;
    }

    public bool Matches(NetworkRequest request)
    {
        var (source, destination, destinationPort, protocol) = request;
        var sourceInRange = SourceIps.Any(item => source >= item.Start && source <= item.End);
        var destinationInRange = DestinationIps.Any(item => destination >= item.Start && destination <= item.End);
        // No ports in ICMP
        var destinationPortInRange = DestinationPorts.Any(item => (destinationPort >= item.Start && destinationPort <= item.End) || protocol.HasFlag(NetworkProtocols.ICMP));

        return protocol != NetworkProtocols.None && sourceInRange && destinationInRange && destinationPortInRange && NetworkProtocols.HasFlag(protocol);
    }
}