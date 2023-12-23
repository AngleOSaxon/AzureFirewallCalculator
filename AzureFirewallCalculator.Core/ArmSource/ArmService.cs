using Azure.ResourceManager;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Network.Models;
using Azure.Core;
using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Core.Tags;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace AzureFirewallCalculator.Core.ArmSource;

public class ArmService(ArmClient client, IDnsResolver dnsResolver, ILogger<ArmService> logger, IMemoryCache cache)
{
    public ArmClient Client { get; } = client;
    public IDnsResolver DnsResolver { get; } = dnsResolver;
    public ILogger<ArmService> Logger { get; } = logger;
    public IMemoryCache Cache { get; } = cache;

    private CancellationTokenSource cacheEviction = new();

    private const string subscriptionCacheKey = "Subscriptions";
    public async Task<List<SubscriptionResource>> GetSubscriptions()
    {
        return (await Cache.GetOrCreateAsync(subscriptionCacheKey, async (entry) =>
        {
            entry.ExpirationTokens.Add(new CancellationChangeToken(cacheEviction.Token));
            var collection = Client.GetSubscriptions();
            List<SubscriptionResource> subscriptions = [];
            await foreach (var item in collection.GetAllAsync())
            {
                subscriptions.Add(item);
            }
            return subscriptions;
        })) ?? [];
    }

    public async Task<List<AzureFirewallData>> GetFirewalls(SubscriptionResource subscription)
    {
        return (await Cache.GetOrCreateAsync(subscription, async (entry) =>
        {
            entry.ExpirationTokens.Add(new CancellationChangeToken(cacheEviction.Token));
            List<AzureFirewallData> firewalls = [];
            await foreach (var item in subscription.GetAzureFirewallsAsync())
            {
                firewalls.Add(item.Data);
            }
            return firewalls;
        })) ?? [];
    }

    public async Task<List<IPGroupData>> GetIpGroups(AzureFirewallData firewall)
    {
        return (await Cache.GetOrCreateAsync(firewall, async (entry) =>
        {
            entry.ExpirationTokens.Add(new CancellationChangeToken(cacheEviction.Token));
            var ipGroups = new List<IPGroupData>();
            var referencedSubscriptions = firewall.IPGroups
                .Select(item => item.Id.SubscriptionId)
                .Concat(firewall.NetworkRuleCollections
                    .SelectMany(item => item.Rules
                        .SelectMany(item => item.SourceIPGroups
                            .Select(item => new ResourceIdentifier(item).SubscriptionId)
                            .Concat(item.DestinationIPGroups
                                .Select(item => new ResourceIdentifier(item).SubscriptionId)
                                )
                            )
                        )
                    )
                .Concat(firewall.ApplicationRuleCollections
                    .SelectMany(item => item.Rules
                        .SelectMany(item => item.SourceIPGroups.Select(item => new ResourceIdentifier(item).SubscriptionId))
                        )
                    )
                .Distinct();
            var subscriptions = Client.GetSubscriptions();
            foreach (var subscriptionId in referencedSubscriptions)
            {
                try
                {
                    var subscription = await subscriptions.GetAsync(subscriptionId);
                    if (subscription == null || subscription.Value == null)
                    {
                        Logger.LogWarning("Unable to load IP Groups for subscription '{subscriptionId}'", subscriptionId);
                        continue;
                    }

                    var subscriptionGroups = subscription.Value.GetIPGroupsAsync();
                    await foreach (var ipGroup in subscriptionGroups)
                    {
                        ipGroups.Add(ipGroup.Data);
                    }
                }
                catch (Exception e)
                {
                    Logger.LogError(e, "Error trying to load IP Groups for subscription '{subscriptionId}': {errorMessage}", subscriptionId, e.Message);
                }
            }

            return ipGroups;
        })) ?? [];
    }

    public async Task<ServiceTag[]> GetServiceTags(SubscriptionResource subscription, string location)
    {
        return (await Cache.GetOrCreateAsync((subscription, location), async (entry) => 
        {
            entry.ExpirationTokens.Add(new CancellationChangeToken(cacheEviction.Token));
             var serviceTags = await subscription.GetServiceTagAsync(location);

            var rawResponse = serviceTags.GetRawResponse();
            if(rawResponse.IsError)
            {
                Logger.LogError("Error loading service tags, error code {errorCode}, error message {errorMessage}", rawResponse.Status, rawResponse.ToString());
            }

            return serviceTags.Value.Values.Select(item => new ServiceTag(Name: item.Name, AddressPrefixes: [.. item.Properties.AddressPrefixes])).ToArray();
        })) ?? [];
    }

    public async Task<Firewall> ConvertToFirewall(AzureFirewallData firewallData, List<IPGroupData> allIpGroups, ServiceTag[] serviceTags)
    {
        return await Cache.GetOrCreateAsync((firewallData, allIpGroups, serviceTags), async (entry) =>
        {
            entry.ExpirationTokens.Add(new CancellationChangeToken(cacheEviction.Token));
            var ipGroups = allIpGroups.ToDictionary(item => item.Id.ToString(), StringComparer.CurrentCultureIgnoreCase);
            var networkRuleCollections = await Task.WhenAll(firewallData.NetworkRuleCollections
                    .Select(async collection => new NetworkRuleCollection
                    (
                        name: collection.Name,
                        priority: collection.Priority ?? 0,
                        action: GetRuleAction(collection.ActionType),
                        rules: await Task.WhenAll(collection.Rules
                            .Select(async item => 
                            {
                                return new NetworkRule(
                                    name: item.Name, 
                                    sourceIps: item.SourceIPGroups
                                        .SelectMany(item => ipGroups[item].IPAddresses)
                                        .Concat(item.SourceAddresses)
                                        .Select(item => RuleIpRange.Parse(item, Logger))
                                        .Where(item => item is not null)
                                        .Cast<RuleIpRange>()
                                        .ToArray(), 
                                    destinationIps: item.DestinationIPGroups
                                        .SelectMany(item => ipGroups[item].IPAddresses)
                                        .Concat(item.DestinationAddresses)
                                        .SelectMany(item => ParseWithServiceTags(item, serviceTags, Logger))
                                        .Concat(await item.DestinationFqdns
                                            .Select(async item => await DnsResolver.ResolveAddress(item))
                                            .SelectManyAsync(async item =>(await item)
                                                .Select(item => new RuleIpRange(start: item, end: item)))
                                        )
                                        .ToArray(),
                                    destinationPorts: item.DestinationPorts
                                        .Select(item => RulePortRange.Parse(item, Logger)!)
                                        .Where(item => item is not null)
                                        .Cast<RulePortRange>()
                                        .ToArray(),
                                    networkProtocols: Utils.ParseNetworkProtocols(item.Protocols.Select(item => item.ToString()).ToArray())
                                );
                            })
                    ))));

            var applicationRuleCollections = firewallData.ApplicationRuleCollections
                .Select(collection => new ApplicationRuleCollection
                (
                    name: collection.Name,
                    priority: collection.Priority ?? 0,
                    action: GetRuleAction(collection.ActionType),
                    rules: collection.Rules
                        .Select(item => new ApplicationRule
                        (
                            name: item.Name,
                            sourceIps: item.SourceIPGroups
                                .SelectMany(item => ipGroups[item].IPAddresses)
                                .Concat(item.SourceAddresses)
                                .Select(item => RuleIpRange.Parse(item, Logger))
                                .Where(item => item is not null)
                                .Cast<RuleIpRange>()
                                .ToArray(),
                            destinationFqdns: item.TargetFqdns.ToArray(),
                            destinationTags: item.FqdnTags.ToArray(),
                            protocols: item.Protocols.Select(item => new ApplicationProtocolPort(Protocol: GetApplicationProtocol(item.ProtocolType), Port: (ushort)(item.Port ?? 0))).ToArray()
                        )).ToArray())
                ).ToArray();

            return new Firewall(
                NetworkRuleCollections: networkRuleCollections,
                ApplicationRuleCollections: applicationRuleCollections
            );
        }) ?? throw new NullReferenceException("This shouldn't be possible");
    }

    public void ResetCache()
    {
        cacheEviction.Cancel();
        cacheEviction = new();
    }

    private static RuleIpRange[] ParseWithServiceTags(string addressRange, ServiceTag[] serviceTags, ILogger logger)
    {
        var result = RuleIpRange.Parse(addressRange, logger);
        if (result != null)
        {
            return [result.Value];
        }

        var serviceTag = serviceTags.FirstOrDefault(item => item.Name.Equals(addressRange, StringComparison.CurrentCultureIgnoreCase));
        if (serviceTag == null)
        {
            return [];
        }

        return serviceTag.AddressPrefixes.Select(item => RuleIpRange.Parse(item, logger))
            .Where(item => item != null)
            .Cast<RuleIpRange>()
            .ToArray();
    }

    private static RuleAction GetRuleAction(AzureFirewallRCActionType? action)
    {
        if (action == AzureFirewallRCActionType.Allow)
        {
            return RuleAction.Allow;
        }
        else if (action == AzureFirewallRCActionType.Deny)
        {
            return RuleAction.Deny;
        }
        throw new ArgumentException($"Unexpected Action '{action}'");
    }

    private static ApplicationProtocol GetApplicationProtocol(AzureFirewallApplicationRuleProtocolType? protocolType)
    {
        if (protocolType == AzureFirewallApplicationRuleProtocolType.Mssql)
        {
            return ApplicationProtocol.Mssql;
        }
        else if (protocolType == AzureFirewallApplicationRuleProtocolType.Https)
        {
            return ApplicationProtocol.Https;
        }
        else if (protocolType == AzureFirewallApplicationRuleProtocolType.Http)
        {
            return ApplicationProtocol.Http;
        }

        throw new ArgumentException($"Unexpected Application Protocol '{protocolType}'");
    }
}