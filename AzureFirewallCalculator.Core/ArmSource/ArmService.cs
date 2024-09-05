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

public class ArmService(ArmClient client, CachingResolver dnsResolver, ILogger<ArmService> logger, IMemoryCache cache)
{
    public ArmClient Client { get; } = client;
    public CachingResolver DnsResolver { get; } = dnsResolver;
    public ILogger<ArmService> Logger { get; } = logger;
    public IMemoryCache Cache { get; } = cache;

    private CancellationTokenSource cacheEviction = new();

    // Cached so that it gets evicted with everything else
    private const string selectedSubscriptionCacheKey = "SelectedSubscription";
    public SubscriptionResource? SelectedSubscription
    {
        get => Cache.Get<SubscriptionResource>(selectedSubscriptionCacheKey);
        set => Cache.Set(selectedSubscriptionCacheKey, value, new CancellationChangeToken(cacheEviction.Token));
    }

    // Cached so that it gets evicted with everything else
    private const string selectedFirewallCacheKey = "SelectedFirewall";
    public AzureFirewallData? SelectedFirewall
    {
        get => Cache.Get<AzureFirewallData>(selectedFirewallCacheKey);
        set => Cache.Set(selectedFirewallCacheKey, value, new CancellationChangeToken(cacheEviction.Token));
    }

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

            var destinationFqdns = firewallData.NetworkRuleCollections
                .SelectMany(item => item.Rules.Select(item => item.DestinationFqdns).SelectMany(item => item))
                .Distinct(StringComparer.OrdinalIgnoreCase);
            // Run lookups for all known DNS entries so that they're cached ahead of time
            var dnsTasks = destinationFqdns.Select(item => DnsResolver.ResolveAddress(item));
            await Task.WhenAll(dnsTasks);

            IEnumerable<RuleIpRange> SafeGetIpGroupRules(string ipGroupId)
            {
                if (ipGroups.TryGetValue(ipGroupId, out var ipGroup))
                {
                    return ipGroup.IPAddresses.Select(item => RuleIpRange.Parse(item, IpSourceType.IpGroup, ipGroup.Name, Logger))
                        .Where(parsedRule => parsedRule != null)
                        .Cast<RuleIpRange>();
                }
                Logger.LogWarning("Did not load IP Group '{ipGroupId}'; some IPs may be missing from rules", ipGroupId);
                return [];
            }

            IEnumerable<RuleIpRange> GetAddressRules(IEnumerable<string> addresses, ServiceTag[]? serviceTags = null)
            {
                if (serviceTags == null)
                {
                    return addresses.Select(item => RuleIpRange.Parse(item, IpSourceType.IpAddress, item, Logger))
                        .Where(parsedRule => parsedRule != null)
                        .Cast<RuleIpRange>();
                }
                return addresses.SelectMany(item => RuleIpRange.Parse(item, serviceTags, IpSourceType.IpAddress, item, Logger));
            }
                    

            var networkRuleCollections = firewallData.NetworkRuleCollections
                    .Select(collection => new NetworkRuleCollection
                    (
                        name: collection.Name,
                        priority: collection.Priority ?? 0,
                        action: GetRuleAction(collection.ActionType),
                        rules: [.. collection.Rules
                            .Select(item => 
                            {
                                return new NetworkRule(
                                    name: item.Name, 
                                    sourceIps: item.SourceIPGroups
                                        .SelectMany(SafeGetIpGroupRules)
                                        .Concat(GetAddressRules(item.SourceAddresses))
                                        .ToArray(), 
                                    destinationIps: item.DestinationIPGroups
                                        .SelectMany(SafeGetIpGroupRules)
                                        .Concat(GetAddressRules(item.DestinationAddresses, serviceTags))
                                        .ToArray(),
                                    destinationFqdns: [.. item.DestinationFqdns],
                                    destinationPorts: item.DestinationPorts
                                        .Select(item => RulePortRange.Parse(item, Logger)!)
                                        .Where(item => item is not null)
                                        .Cast<RulePortRange>()
                                        .ToArray(),
                                    networkProtocols: Utils.ParseNetworkProtocols(item.Protocols.Select(item => item.ToString()).ToArray()),
                                    dnsResolver: DnsResolver
                                );
                            })]
                    ));

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
                                .SelectMany(SafeGetIpGroupRules)
                                .Concat(GetAddressRules(item.SourceAddresses))
                                .ToArray(),
                            destinationFqdns: item.TargetFqdns.ToArray(),
                            destinationTags: item.FqdnTags.ToArray(),
                            protocols: item.Protocols.Select(item => new ApplicationProtocolPort(Protocol: GetApplicationProtocol(item.ProtocolType), Port: (ushort)(item.Port ?? 0))).ToArray()
                        )).ToArray())
                ).ToArray();

            return new Firewall(
                NetworkRuleCollections: [.. networkRuleCollections],
                ApplicationRuleCollections: [.. applicationRuleCollections]
            );
        }) ?? throw new NullReferenceException("This shouldn't be possible");
    }

    public void ResetCache()
    {
        cacheEviction.Cancel();
        DnsResolver.FlushCache();
        cacheEviction = new();
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