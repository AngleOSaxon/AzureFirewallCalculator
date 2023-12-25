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

    /// <summary>
    /// Clone this rule with the <see cref="this.DestinationFqdns" /> removed and the resolved IPs
    /// from the FQDNs added to the list of <see cref="this.DestinationIps"/>.  Allows the rule
    /// to be used as if the FQDNs had been resolved at rule creation, the way they were in earlier
    /// iterations of the program
    /// </summary>
    /// <param name="resolvedIps">The IPs that were resolved from <see cref="DestinationFqdns"/> using <see cref="DnsResolver"/></param>
    /// <returns>A clone of this <see cref="NetworkRule"/></returns>
    private NetworkRule CloneWithResolvedIps(RuleIpRange[] resolvedIps) => new (
            name: Name,
            sourceIps: SourceIps,
            destinationIps: [.. DestinationIps, .. resolvedIps],
            destinationFqdns: [],
            destinationPorts: DestinationPorts,
            networkProtocols: NetworkProtocols,
            dnsResolver: DnsResolver
        );

    public async Task<NetworkRuleMatch> Matches(NetworkRequest request)
    {
        var (source, destination, destinationPort, protocol) = request;
        var sourcesInRange = source == null
            ? SourceIps 
            : SourceIps.Where(item => source >= item.Start && source <= item.End).ToArray();

        var resolvedFqdns = (await Task.WhenAll(DestinationFqdns.Select(item => DnsResolver.ResolveAddress(item))))
            .SelectMany(item => item.Select(ip => new RuleIpRange(ip, ip)))
            .ToArray();
        var destinationIps = DestinationIps
            .Concat(resolvedFqdns)
            .ToArray();
        
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
            Rule: CloneWithResolvedIps(resolvedFqdns) // Clone this rule so that it will show the resolved IPs on the UI
        );
    }
}