using System.Data;
using AzureFirewallCalculator.Core.Dns;

namespace AzureFirewallCalculator.Core;

public record class NetworkRule
{
    public string Name { get;}

    public RuleIpRange[] SourceIps { get; }

    public RuleIpRange[] DestinationIps { get; }

    public string[] DestinationFqdns { get; }

    public RulePortRange[] DestinationPorts { get; }

    public NetworkProtocols NetworkProtocols { get; }

    public IDnsResolver DnsResolver { get; }

    public NetworkRule(string name, RuleIpRange[] sourceIps, RuleIpRange[] destinationIps, RulePortRange[] destinationPorts, string[] destinationFqdns, NetworkProtocols networkProtocols, IDnsResolver dnsResolver)
    {
        Name = name;
        SourceIps = sourceIps;
        DestinationIps = destinationIps;
        DestinationPorts = destinationPorts;
        DestinationFqdns = destinationFqdns;
        NetworkProtocols = networkProtocols;
        DnsResolver = dnsResolver;
    }

    public async Task<NetworkRuleMatch> Matches(NetworkRequest request)
    {
        var (source, destination, destinationPort, protocol) = request;
        var sourcesInRange = source == null
            ? SourceIps 
            : SourceIps.Where(item => source >= item.Start && source <= item.End).ToArray();

        var resolvedFqdns = await Task.WhenAll(DestinationFqdns.Select(item => DnsResolver.ResolveAddress(item)));
        var destinationIps = DestinationIps
            .Concat(resolvedFqdns
                .SelectMany(item => item.Select(ip => new RuleIpRange(ip, ip)))
            ).ToArray();
        
        var destinationsInRange = destination == null
            ? destinationIps
            : destinationIps.Where(item => destination >= item.Start && destination <= item.End).ToArray();
        // No ports in ICMP
        var destinationPortInRange = request.DestinationPort == null
            ? DestinationPorts
            : DestinationPorts.Where(item => (destinationPort >= item.Start && destinationPort <= item.End) || protocol.HasFlag(NetworkProtocols.ICMP));

        var matchedProtocols = request.Protocol & NetworkProtocols;

        return new NetworkRuleMatch(
            Matched: protocol != NetworkProtocols.None && sourcesInRange.Length != 0 && destinationsInRange.Length != 0 && destinationPortInRange.Any() && NetworkProtocols.HasFlag(protocol),
            MatchedSourceIps: sourcesInRange,
            MatchedDestinationIps: destinationsInRange,
            MatchedProtocols: matchedProtocols,
            MatchedPorts: destinationPortInRange.ToArray(),
            Rule: this
        );
    }
}