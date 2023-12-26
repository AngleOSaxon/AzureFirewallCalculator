using AzureFirewallCalculator.Core.Dns;

namespace AzureFirewallCalculator.Core;

public class RuleProcessor(IDnsResolver dnsResolver, Firewall firewall)
{
    public IDnsResolver DnsResolver { get; } = dnsResolver;
    public Firewall Firewall { get; } = firewall;

    private readonly NetworkProcessingResponseComparer Comparer = new();

    public async Task<NetworkProcessingResponse[]> ProcessNetworkRequests(NetworkRequest[] networkRequests)
    {
        var networkRequestResults = new List<NetworkProcessingResponse>();

        foreach (var request in networkRequests)
        {
            foreach (var collection in Firewall.NetworkRuleCollections)
            {
                var matches = await collection.GetMatches(request);
                if (matches.Length > 0)
                {
                    networkRequestResults.Add(new NetworkProcessingResponse(collection.Priority, collection.Name, collection.RuleAction, matches));
                }
            }
        }

        return [.. networkRequestResults.Distinct(Comparer).OrderBy(item => item.Priority)];
    }

    public async Task<NetworkProcessingResponse[]> ProcessNetworkRequest(NetworkRequest networkRequest) => await ProcessNetworkRequests([networkRequest]);

    public async Task<ProcessingResponseBase[]> ProcessApplicationRequest(ApplicationRequest applicationRequest)
    {
        var responseSeed = new List<ProcessingResponseBase>();
        var networkRequests = applicationRequest.DestinationFqdn != "*"
            ? 
                (await DnsResolver.ResolveAddress(applicationRequest.DestinationFqdn))
                .Select(ip => new NetworkRequest (
                    sourceIp: applicationRequest.SourceIp,
                    destinationIp: ip,
                    destinationPort: applicationRequest.Protocol.Port,
                    protocol: NetworkProtocols.TCP // I don't think there's any UDP protocols?  Maybe also have UDP for everything?  Maybe just Any?
                ))
                .ToArray()
            :
                [
                    new (
                        sourceIp: applicationRequest.SourceIp,
                        destinationIp: null,
                        applicationRequest.Protocol.Port,
                        protocol: NetworkProtocols.TCP // I don't think there's any UDP protocols?  Maybe also have UDP for everything?  Maybe just Any?
                    ) 
                ];

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