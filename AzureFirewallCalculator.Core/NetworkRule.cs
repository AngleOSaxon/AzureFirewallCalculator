using System.Data;
using AzureFirewallCalculator.Core.Dns;

namespace AzureFirewallCalculator.Core;

public record class NetworkRule
{
    public string Name { get; init; }

    public RuleIpRange[] SourceIps { get; init; }

    public RuleIpRange[] DestinationIps { get; init; }

    public string[] DestinationFqdns { get; init; }

    public RulePortRange[] DestinationPorts { get; init; }

    public NetworkProtocols NetworkProtocols { get; init; }

    public IDnsResolver DnsResolver { get; init; }

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

    public async Task<NetworkRuleMatch> Matches(IEnumerable<NetworkRequest> requests)
    {
        List<RuleIpRange> allSourcesInRange = [];
        List<RuleIpRange> allDestinationsInRange = [];
        List<RulePortRange> allDestinationPorts = [];
        NetworkProtocols matchedProtocols = NetworkProtocols.None;

        var resolvedFqdns = (await Task.WhenAll(DestinationFqdns.Select(DnsResolver.ResolveAddress)))
            .SelectMany(item => item.Select(ip => new RuleIpRange(ip, ip)))
            .ToArray();

        foreach (var request in requests)
        {
            var (source, destination, destinationPort, protocol) = request;
            var sourcesInRange = source == null
                ? SourceIps 
                : SourceIps.Where(item => source >= item.Start && source <= item.End).ToArray();
            allSourcesInRange.AddRange(sourcesInRange);

            var destinationIps = DestinationIps
                .Concat(resolvedFqdns)
                .ToArray();
            
            var destinationsInRange = destination == null
                ? destinationIps
                : destinationIps.Where(item => destination >= item.Start && destination <= item.End).ToArray();
            allDestinationsInRange.AddRange(destinationsInRange);

            // No ports in ICMP
            var destinationPortsInRange = request.DestinationPort == null
                ? DestinationPorts
                : DestinationPorts.Where(item => (destinationPort >= item.Start && destinationPort <= item.End) || protocol.HasFlag(NetworkProtocols.ICMP));
            allDestinationPorts.AddRange(destinationPortsInRange);

            matchedProtocols |= request.Protocol & NetworkProtocols;
        }

        return new NetworkRuleMatch(
            Matched: matchedProtocols != NetworkProtocols.None && allSourcesInRange.Count != 0 && allDestinationsInRange.Count != 0 && allDestinationPorts.Count != 0 && NetworkProtocols.HasFlag(matchedProtocols),
            MatchedSourceIps: [.. allSourcesInRange.Distinct().OrderBy(item => item.Start)],
            MatchedDestinationIps: [.. allDestinationsInRange.Distinct().OrderBy(item => item.Start)],
            MatchedProtocols: matchedProtocols,
            MatchedPorts: [.. allDestinationPorts.Distinct().OrderBy(item => item.Start)],
            Rule: this with 
            {
                DestinationIps = [..DestinationIps.Concat(resolvedFqdns)]
            }
        );
    }

    public override string ToString()
    {
        return $"{string.Join(',', SourceIps)} to {string.Join(',', DestinationIps)} on {NetworkProtocols}/{string.Join(',', DestinationPorts)}";
    }
}