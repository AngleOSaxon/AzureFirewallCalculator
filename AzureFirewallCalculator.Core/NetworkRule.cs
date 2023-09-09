using System.Data;

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

    public NetworkRuleMatch Matches(NetworkRequest request)
    {
        var (source, destination, destinationPort, protocol) = request;
        var sourcesInRange = SourceIps.Where(item => source >= item.Start && source <= item.End).ToArray();
        var destinationsInRange = DestinationIps.Where(item => destination >= item.Start && destination <= item.End).ToArray();
        // No ports in ICMP
        var destinationPortInRange = DestinationPorts.Any(item => (destinationPort >= item.Start && destinationPort <= item.End) || protocol.HasFlag(NetworkProtocols.ICMP));

        return new NetworkRuleMatch(
            Matched: protocol != NetworkProtocols.None && sourcesInRange.Any() && destinationsInRange.Any() && destinationPortInRange && NetworkProtocols.HasFlag(protocol),
            MatchedSourceIps: sourcesInRange,
            MatchedDestinationIps: destinationsInRange,
            Rule: this
        );
    }
}