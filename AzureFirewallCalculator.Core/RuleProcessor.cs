using System.Collections.ObjectModel;
using AzureFirewallCalculator.Core.Dns;

namespace AzureFirewallCalculator.Core;

public class RuleProcessor(IDnsResolver dnsResolver, Firewall firewall)
{
    public IDnsResolver DnsResolver { get; } = dnsResolver;
    public Firewall Firewall { get; } = firewall;

    public async Task<ProcessingResponseBase[]> ProcessNetworkRequests(NetworkRequest[] networkRequests)
    {
        var responseTasks = Firewall.NetworkRuleCollections.Select(async collection => new NetworkProcessingResponse(
            Priority: collection.Priority,
            CollectionName: collection.Name,
            RuleAction: collection.RuleAction,
            MatchedRules: await collection.GetMatches(networkRequests)
        ));
        var responses = await Task.WhenAll(responseTasks);

        return [.. responses.Where(item => item.MatchedRules.Length > 0).OrderBy(item => item.Priority)];
    }

    public async Task<ProcessingResponseBase[]> ProcessNetworkRequest(NetworkRequest networkRequest) => await ProcessNetworkRequests([networkRequest]);

    public async Task<ProcessingResponseBase[]> ProcessApplicationRequest(ApplicationRequest applicationRequest)
    {
        var responseSeed = new List<ProcessingResponseBase>();
        uint?[] destinationIps = applicationRequest.DestinationFqdn != "*"
            ? [.. (await DnsResolver.ResolveAddress(applicationRequest.DestinationFqdn)).Cast<uint?>()]
            : [null];
        var networkRequests = destinationIps.Select(ip => new NetworkRequest(
            sourceIp: applicationRequest.SourceIp,
            destinationIp: ip,
            destinationPort: applicationRequest.Protocol.Port,
            protocol: NetworkProtocols.TCP // I don't think there's any UDP protocols?  Maybe also have UDP for everything?  Maybe just Any?
        )).ToArray();

        var networkRequestTask = Task.Run(() => ProcessNetworkRequests(networkRequests));

        var results = Firewall.ApplicationRuleCollections.Aggregate(responseSeed, (accumulator, collection) =>
        {
            var matches = collection.GetMatches(applicationRequest);
            if (matches.Length != 0)
            {
                accumulator.Add(new ApplicationProcessingResponse(collection.Priority, collection.Name, collection.RuleAction, MatchedRules: matches));
            }
            return accumulator;
        });

        var networkResults = await networkRequestTask;

        return [.. networkResults.OrderBy(item => item.Priority), .. results.Distinct().OrderBy(item => item.Priority)];
    }
}