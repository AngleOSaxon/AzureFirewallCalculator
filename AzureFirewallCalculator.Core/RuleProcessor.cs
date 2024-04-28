using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using AzureFirewallCalculator.Core.Dns;

namespace AzureFirewallCalculator.Core;

public class RuleProcessor(IDnsResolver dnsResolver, Firewall firewall)
{
    public IDnsResolver DnsResolver { get; } = dnsResolver;
    public Firewall Firewall { get; } = firewall;

    private readonly ushort[] ApplicationPorts = [80, 443, 1433];

    public async Task<ProcessingResponseBase[]> ProcessNetworkRequests(IEnumerable<NetworkRequest> networkRequests)
    {
        var responseTasks = Firewall.NetworkRuleCollections.Select(async collection => new NetworkProcessingResponse(
            GroupPriority: collection.GroupPriority,
            Priority: collection.Priority,
            CollectionName: collection.Name,
            RuleAction: collection.RuleAction,
            MatchedRules: await collection.GetMatches(networkRequests)
        ));

        var nonstandardApplicationSearches = networkRequests.Where(item => item.DestinationPort == null || !ApplicationPorts.Contains(item.DestinationPort.Value))
        .SelectMany<NetworkRequest, ApplicationRequest>(item => 
        [
            new ApplicationRequest(
                numericSourceIp: item.SourceIp,
                destinationFqdn: "*",
                protocol: new ApplicationProtocolPort(ApplicationProtocol.Http, item.DestinationPort)
            ),
            new ApplicationRequest(
                numericSourceIp: item.SourceIp,
                destinationFqdn: "*",
                protocol: new ApplicationProtocolPort(ApplicationProtocol.Https, item.DestinationPort)
            ),
            new ApplicationRequest(
                numericSourceIp: item.SourceIp,
                destinationFqdn: "*",
                protocol: new ApplicationProtocolPort(ApplicationProtocol.Mssql, item.DestinationPort)
            ),
        ]);

        var applicationResults = Firewall.ApplicationRuleCollections.Select(collection => new ApplicationProcessingResponse(
            GroupPriority: collection.GroupPriority,
            Priority: collection.Priority,
            CollectionName: collection.Name,
            RuleAction: collection.RuleAction,
            MatchedRules: collection.GetMatches(nonstandardApplicationSearches)
        ));

        var responses = await Task.WhenAll(responseTasks);

        List<ProcessingResponseBase> results = [..responses.Where(item => item.MatchedRules.Length > 0).OrderBy(item => item.Priority)];
        results.AddRange(applicationResults.Where(item => item.MatchedRules.Length > 0).OrderBy(item => item.Priority));

        return [..results];
    }

    public async Task<ProcessingResponseBase[]> ProcessNetworkRequest(NetworkRequest networkRequest) => await ProcessNetworkRequests([networkRequest]);

    public async Task<ProcessingResponseBase[]> ProcessApplicationRequests(ApplicationRequest[] applicationRequests)
    {
        var networkRequestTasks = applicationRequests.Select(async applicationRequest =>
        {
            uint?[] destinationIps = applicationRequest.DestinationFqdn != "*"
                ? [.. (await DnsResolver.ResolveAddress(applicationRequest.DestinationFqdn)).Cast<uint?>()]
                : [null];
            var networkRequests = destinationIps.Select(ip => new NetworkRequest(
                sourceIp: applicationRequest.SourceIp,
                destinationIp: ip,
                destinationPort: applicationRequest.Protocol.Port,
                protocol: NetworkProtocols.TCP // I don't think there's any UDP protocols?  Maybe also have UDP for everything?  Maybe just Any?
            ));
            return networkRequests;
        });
        var networkRequests = (await Task.WhenAll(networkRequestTasks)).SelectMany(item => item);

        var networkRequestProcessing = Task.Run(() => ProcessNetworkRequests(networkRequests));
        
        var applicationResults = Firewall.ApplicationRuleCollections.Select(collection => new ApplicationProcessingResponse(
            GroupPriority: collection.GroupPriority,
            Priority: collection.Priority,
            CollectionName: collection.Name,
            RuleAction: collection.RuleAction,
            MatchedRules: collection.GetMatches(applicationRequests)
        ));
        var networkResults = await networkRequestProcessing;

        return [..networkResults, .. applicationResults.Where(item => item.MatchedRules.Length > 0).OrderBy(item => item.Priority)];
    }

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
                accumulator.Add(new ApplicationProcessingResponse(collection.GroupPriority, collection.Priority, collection.Name, collection.RuleAction, MatchedRules: matches));
            }
            return accumulator;
        });

        var networkResults = await networkRequestTask;

        return [.. networkResults.OrderBy(item => item.GroupPriority).ThenBy(item => item.Priority), .. results.Distinct().OrderBy(item => item.Priority)];
    }
}