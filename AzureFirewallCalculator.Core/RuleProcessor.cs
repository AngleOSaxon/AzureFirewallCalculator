using AzureFirewallCalculator.Core.Dns;

namespace AzureFirewallCalculator.Core;

public class RuleProcessor
{
    public RuleProcessor(IDnsResolver dnsResolver, Firewall firewall)
    {
        DnsResolver = dnsResolver;
        Firewall = firewall;
    }

    public IDnsResolver DnsResolver { get; }
    public Firewall Firewall { get; }

    public NetworkProcessingResponse[] ProcessNetworkRequests(NetworkRequest[] networkRequests)
    {
        var responseSeed = new List<NetworkProcessingResponse>();
        var networkRequestResults = Firewall.NetworkRuleCollections.Aggregate(responseSeed, (accumulator, collection) => 
        {
            var matches = networkRequests.SelectMany(request => collection.GetMatches(request)).ToArray();
            if (matches.Any())
            {
                accumulator.Add(new NetworkProcessingResponse(collection.Priority, collection.Name, collection.RuleAction, matches));
            }
            return accumulator;
        });

        return networkRequestResults.Distinct().OrderBy(item => item.Priority).ToArray();
    }

    public NetworkProcessingResponse[] ProcessNetworkRequest(NetworkRequest networkRequest) => ProcessNetworkRequests(new NetworkRequest[] { networkRequest });

    public async Task<ProcessingResponseBase[]> ProcessApplicationRequest(ApplicationRequest applicationRequest)
    {
        var responseSeed = new List<ProcessingResponseBase>();
        var ips = await DnsResolver.ResolveAddress(applicationRequest.DestinationFqdn);
        var networkRequests = ips.Select(ip => new NetworkRequest (
            sourceIp: applicationRequest.SourceIp,
            destinationIp: ip,
            destinationPort: applicationRequest.Protocol.Port,
            protocol: NetworkProtocols.TCP // I don't think there's any UDP protocols?  Maybe also have UDP for everything?  Maybe just Any?
        ))
        .ToArray();

        var networkRequestTask = Task.Run(() => ProcessNetworkRequests(networkRequests));

        var results = Firewall.ApplicationRuleCollections.Aggregate(responseSeed, (accumulator, collection) => 
        {
            var matches = collection.GetMatches(applicationRequest);
            if (matches.Any())
            {
                accumulator.Add(new ApplicationProcessingResponse(collection.Priority, collection.Name, collection.RuleAction, MatchedRules: matches));
            }
            return accumulator;
        });

        var networkResults = await networkRequestTask;

        return networkResults.Distinct().OrderBy(item => item.Priority).Concat(results.Distinct().OrderBy(item => item.Priority)).ToArray();
    }
}