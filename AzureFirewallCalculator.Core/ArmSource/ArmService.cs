using Azure.ResourceManager;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Network.Models;
using Azure.Core;
using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Core.Tags;

namespace AzureFirewallCalculator.Core.ArmSource;

public class ArmService
{
    public ArmService(ArmClient client, IDnsResolver dnsResolver)
    {
        Client = client;
        DnsResolver = dnsResolver;
    }

    public ArmClient Client { get; }
    public IDnsResolver DnsResolver { get; }

    public async Task<List<SubscriptionResource>> GetSubscriptions()
    {
        var collection = Client.GetSubscriptions();
        List<SubscriptionResource> subscriptions = new();
        await foreach (var item in collection.GetAllAsync())
        {
            subscriptions.Add(item);
        }
        return subscriptions;
    }

    public async Task<List<AzureFirewallData>> GetFirewalls(SubscriptionResource subscription)
    {
        List<AzureFirewallData> firewalls = new();
        await foreach (var item in subscription.GetAzureFirewallsAsync())
        {
            firewalls.Add(item.Data);
        }
        return firewalls;
    }

    public async Task<List<IPGroupData>> GetIpGroups(AzureFirewallData firewall)
    {
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
            var subscription = await subscriptions.GetAsync(subscriptionId);
            if (subscription == null || subscription.Value == null)
            {
                // TODO: logging.  Alert user some IP Groups are unknown
                continue;
            }

            var subscriptionGroups = subscription.Value.GetIPGroupsAsync();
            await foreach (var ipGroup in subscriptionGroups)
            {
                ipGroups.Add(ipGroup.Data);
            }
        }

        return ipGroups;
    }

    public async Task<ServiceTagsListResult?> GetServiceTags(SubscriptionResource subscription, string location)
    {
        var serviceTags = await subscription.GetServiceTagAsync(location);

        return serviceTags?.Value;
    }

    public async Task<Firewall> ConvertToFirewall(AzureFirewallData firewallData, List<IPGroupData> allIpGroups, ServiceTagsListResult serviceTags)
    {
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
                                    .Select(item => RuleIpRange.Parse(item))
                                    .Where(item => item is not null)
                                    .Cast<RuleIpRange>()
                                    .ToArray(), 
                                destinationIps: item.DestinationIPGroups
                                    .SelectMany(item => ipGroups[item].IPAddresses)
                                    .Concat(item.DestinationAddresses)
                                    .SelectMany(item => ParseWithServiceTags(item, serviceTags))
                                    .Concat(await item.DestinationFqdns
                                        .Select(async item => await DnsResolver.ResolveAddress(item))
                                        .SelectManyAsync(async item =>(await item)
                                            .Select(item => new RuleIpRange(start: item, end: item)))
                                    )
                                    .ToArray(),
                                destinationPorts: item.DestinationPorts
                                    .Select(item => RulePortRange.Parse(item)!)
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
                        sourceAddresses: item.SourceIPGroups
                            .SelectMany(item => ipGroups[item].IPAddresses)
                            .Concat(item.SourceAddresses)
                            .Select(item => RuleIpRange.Parse(item))
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
    }

    private static RuleIpRange[] ParseWithServiceTags(string addressRange, ServiceTagsListResult serviceTags)
    {
        var result = RuleIpRange.Parse(addressRange);
        if (result != null)
        {
            return new RuleIpRange[] { result.Value };
        }

        var serviceTag = serviceTags.Values.FirstOrDefault(item => item.Name.Equals(addressRange, StringComparison.CurrentCultureIgnoreCase));
        if (serviceTag == null)
        {
            return Array.Empty<RuleIpRange>();
        }

        return serviceTag.Properties.AddressPrefixes.Select(RuleIpRange.Parse)
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