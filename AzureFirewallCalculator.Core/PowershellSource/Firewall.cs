using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Core.Tags;
using Microsoft.Extensions.Logging;

namespace AzureFirewallCalculator.Core.PowershellSource;

public record struct Firewall
{
    public string Name { get; set; }

    public NetworkRuleCollection[] NetworkRuleCollections { get; set; }

    public ApplicationRuleCollection[] ApplicationRuleCollections { get; set; }

    public ResourceId FirewallPolicy { get; set; }

    public readonly async Task<Core.Firewall> ConvertToFirewall(Dictionary<string, IpGroup> ipGroups, CachingResolver resolver, ILogger logger)
    {
        var serviceTags = await ServiceTagImporter.GetServiceTags(DateTimeOffset.UtcNow);
        return await ConvertToFirewall(ipGroups, [], resolver, serviceTags, logger);
    }

    public readonly async Task<Core.Firewall> ConvertToFirewall(Dictionary<string, IpGroup> ipGroups, Dictionary<string, Policy> policies, Dictionary<string, RuleCollectionGroup> ruleCollectionGroups, CachingResolver resolver, ILogger logger)
    {
        var serviceTags = await ServiceTagImporter.GetServiceTags(DateTimeOffset.UtcNow);

        return await ConvertToFirewall(ipGroups, policies, ruleCollectionGroups, resolver, serviceTags, logger);
    }

    public readonly async Task<Core.Firewall> ConvertToFirewall(Dictionary<string, IpGroup> ipGroups, Dictionary<string, Policy> policies, Dictionary<string, RuleCollectionGroup> ruleCollectionGroups, CachingResolver resolver, ServiceTag[] serviceTags, ILogger logger)
    {
        RuleCollectionGroup[] ruleCollectionGroupsFromPolicy = [];
        if (policies.TryGetValue(FirewallPolicy.Id, out var policy))
        {
            ruleCollectionGroupsFromPolicy = policy.RuleCollectionGroups.Select(item => 
            {
                if (ruleCollectionGroups.TryGetValue(item.Id, out var ruleCollectionGroup))
                {
                    return ruleCollectionGroup;
                }
                logger.LogError("Unable to find RuleCollectionGroup with id {ruleCollectionGroupId}.  Rules from this group will not be loaded.", item.Id);
                return null!;
            })
            .Where(item => item != null)
            .ToArray();
        }
        else
        {
            logger.LogError("Unable to find Policy with id {policyId}.  Rules from this policy will not be loaded.", FirewallPolicy.Id);
        }

        return await ConvertToFirewall(ipGroups, ruleCollectionGroupsFromPolicy, resolver, serviceTags, logger);
    }

    public readonly async Task<Core.Firewall> ConvertToFirewall(Dictionary<string, IpGroup> ipGroups,
                                                                RuleCollectionGroup[] ruleCollectionGroups,
                                                                CachingResolver resolver,
                                                                ServiceTag[] serviceTags,
                                                                ILogger logger)
    {
        var destinationFqdns = NetworkRuleCollections
                .SelectMany(item => item.Rules.Select(item => item.DestinationFqdns).SelectMany(item => item))
                .Distinct(StringComparer.OrdinalIgnoreCase);
        // Run lookups for all known DNS entries so that they're cached ahead of time
        var dnsTasks = destinationFqdns.Select(resolver.ResolveAddress);
        await Task.WhenAll(dnsTasks);

        var networkRuleConverter = SetupNetworkRuleConverter(ipGroups, serviceTags, resolver, logger);
        var applicationRuleConverter = SetupApplicationRuleConverter(ipGroups, logger);

        var networkRuleCollections = NetworkRuleCollections
                .Select(collection => new Core.NetworkRuleCollection
                (
                    name: collection.Name,
                    priority: collection.Priority,
                    action: Enum.Parse<Core.RuleAction>(collection.Action.Type),
                    rules: [.. collection.Rules
                        .Concat(
                            ruleCollectionGroups
                                .SelectMany(item => item.Properties.RuleCollection
                                    .Where(item => item.Rules.IsT0)
                                .SelectMany(item => item.Rules.AsT0)
                            )
                        )
                        .Select(networkRuleConverter)
                        ]
                ))
                .Concat(
                ruleCollectionGroups.SelectMany(group => group.Properties.RuleCollection
                    .Where(ruleCollection => ruleCollection.Rules.IsT0)
                    .Select(ruleCollection => new Core.NetworkRuleCollection(
                        name: ruleCollection.Name,
                        groupPriority: group.Properties.Priority,
                        priority: ruleCollection.Priority,
                        action: Enum.Parse<Core.RuleAction>(ruleCollection.Action.Type),
                        rules: [..ruleCollection.Rules.AsT0.Select(networkRuleConverter)]
                    ))
                )
            );

        var applicationRuleCollections = ApplicationRuleCollections
            .Select(collection => new Core.ApplicationRuleCollection
            (
                name: collection.Name,
                priority: collection.Priority,
                action: Enum.Parse<Core.RuleAction>(collection.Action.Type),
                rules: [..collection.Rules.Select(applicationRuleConverter)]
            ))
            .Concat(
                ruleCollectionGroups.SelectMany(group => group.Properties.RuleCollection
                    .Where(ruleCollection => ruleCollection.Rules.IsT1)
                    .Select(ruleCollection => new Core.ApplicationRuleCollection(
                        name: ruleCollection.Name,
                        groupPriority: group.Properties.Priority,
                        priority: ruleCollection.Priority,
                        action: Enum.Parse<Core.RuleAction>(ruleCollection.Action.Type),
                        rules: [..ruleCollection.Rules.AsT1.Select(applicationRuleConverter)]
                    ))
                )
            );

        return new Core.Firewall
        (
            NetworkRuleCollections: [.. networkRuleCollections],
            ApplicationRuleCollections: [.. applicationRuleCollections]
        );
    }

    private static IList<string> SafeGetIpGroupAddresses(string ipGroupId, Dictionary<string, IpGroup> ipGroups, ILogger logger)
    {
        if (ipGroups.TryGetValue(ipGroupId, out var ipGroup))
        {
            return ipGroup.IpAddresses;
        }
        logger.LogWarning("Did not load IP Group '{ipGroupId}'; some IPs may be missing from rules", ipGroupId);
        return [];
    }

    private static IEnumerable<RuleIpRange> SafeGetIpGroupRules(string ipGroupId, Dictionary<string, IpGroup> ipGroups, ILogger logger)
    {
        if (ipGroups.TryGetValue(ipGroupId, out var ipGroup))
        {
            var name = ipGroupId.Split('/')[^1];
            return ipGroup.IpAddresses.Select(item => RuleIpRange.Parse(item, IpSourceType.IpGroup, name, logger))
                .Where(parsedRule => parsedRule != null)
                .Cast<RuleIpRange>();
        }
        logger.LogWarning("Did not load IP Group '{ipGroupId}'; some IPs may be missing from rules", ipGroupId);
        return [];
    }

    private static IEnumerable<RuleIpRange> GetAddressRules(IEnumerable<string> addresses, ILogger logger, ServiceTag[]? serviceTags = null)
    {
        if (serviceTags == null)
        {
            return addresses.Select(item => RuleIpRange.Parse(item, IpSourceType.IpAddress, item, logger))
                .Where(parsedRule => parsedRule != null)
                .Cast<RuleIpRange>();
        }
        return addresses.SelectMany(item => RuleIpRange.Parse(item, serviceTags, IpSourceType.IpAddress, item, logger));
    }

    private static Func<NetworkRule, Core.NetworkRule> SetupNetworkRuleConverter(Dictionary<string, IpGroup> ipGroups, ServiceTag[] serviceTags, IDnsResolver resolver, ILogger logger)
    {
        return (NetworkRule item) => ConvertNetworkRule(item, ipGroups, serviceTags, resolver, logger);
    }

    private static Core.NetworkRule ConvertNetworkRule(NetworkRule item, Dictionary<string, IpGroup> ipGroups, ServiceTag[] serviceTags, IDnsResolver resolver, ILogger logger)
        => new 
        (
            name: item.Name, 
            sourceIps: item.SourceIpGroups
                .SelectMany(item => SafeGetIpGroupRules(item, ipGroups, logger))
                .Concat(GetAddressRules(item.SourceAddresses, logger))
                .ToArray(), 
            destinationIps: item.DestinationIpGroups
                .SelectMany(item => SafeGetIpGroupRules(item, ipGroups, logger))
                .Concat(GetAddressRules(item.DestinationAddresses, logger, serviceTags))
                .ToArray(),
            destinationFqdns: item.DestinationFqdns,
            destinationPorts: item.DestinationPorts
                .Select(item => RulePortRange.Parse(item, logger)!)
                .Where(item => item is not null)
                .Cast<RulePortRange>()
                .ToArray(),
            networkProtocols: Utils.ParseNetworkProtocols(item.Protocols),
            dnsResolver: resolver
        );

    private static Func<ApplicationRule, Core.ApplicationRule> SetupApplicationRuleConverter(Dictionary<string, IpGroup> ipGroups, ILogger logger)
    {
        return (ApplicationRule item) => ConvertApplicationRule(item, ipGroups, logger);
    }

    private static Core.ApplicationRule ConvertApplicationRule(ApplicationRule item, Dictionary<string, IpGroup> ipGroups, ILogger logger)
        => new
        (
            name: item.Name,
            sourceIps: item.SourceIpGroups
                .SelectMany(item => SafeGetIpGroupRules(item, ipGroups, logger))
                .Concat(GetAddressRules(item.SourceAddresses, logger))
                .ToArray(),
            destinationFqdns: item.TargetFqdns,
            destinationTags: item.FqdnTags,
            protocols: item.Protocols.Select(item => new Core.ApplicationProtocolPort(Protocol: Enum.Parse<Core.ApplicationProtocol>(item.ProtocolType), Port: item.Port)).ToArray()
        );
}