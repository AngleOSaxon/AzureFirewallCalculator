using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Core.Tags;
using Microsoft.Extensions.Logging;

namespace AzureFirewallCalculator.Core.PowershellSource;

public record struct Firewall
{
    public string Name { get; set; }

    public NetworkRuleCollection[] NetworkRuleCollections { get; set; }

    public ApplicationRuleCollection[] ApplicationRuleCollections { get; set; }

    public readonly async Task<Core.Firewall> ConvertToFirewall(Dictionary<string, IpGroup> ipGroups, CachingResolver resolver, ILogger logger)
    {
        var serviceTags = await ServiceTagImporter.GetServiceTags(DateTimeOffset.UtcNow);
        return await ConvertToFirewall(ipGroups, resolver, serviceTags, logger);
    }

    public readonly async Task<Core.Firewall> ConvertToFirewall(Dictionary<string, IpGroup> ipGroups, CachingResolver resolver, ServiceTag[] serviceTags, ILogger logger)
    {
        var destinationFqdns = NetworkRuleCollections
                .SelectMany(item => item.Rules.Select(item => item.DestinationFqdns).SelectMany(item => item))
                .Distinct(StringComparer.OrdinalIgnoreCase);
        // Run lookups for all known DNS entries so that they're cached ahead of time
        var dnsTasks = destinationFqdns.Select(resolver.ResolveAddress);
        await Task.WhenAll(dnsTasks);

        var networkRuleCollections = NetworkRuleCollections
                .Select(collection => new Core.NetworkRuleCollection
                (
                    name: collection.Name,
                    priority: collection.Priority,
                    action: Enum.Parse<Core.RuleAction>(collection.Action.Type),
                    rules: [.. collection.Rules
                        .Select(item => 
                        {
                            return new Core.NetworkRule(
                                name: item.Name, 
                                sourceIps: item.SourceIpGroups
                                    .SelectMany(item => ipGroups[item].IpAddresses)
                                    .Concat(item.SourceAddresses)
                                    .Select(item => RuleIpRange.Parse(item, logger))
                                    .Where(item => item is not null)
                                    .Cast<RuleIpRange>()
                                    .ToArray(), 
                                destinationIps: item.DestinationIpGroups
                                    .SelectMany(item => ipGroups[item].IpAddresses)
                                    .Concat(item.DestinationAddresses)
                                    .SelectMany(item => RuleIpRange.Parse(item, serviceTags, logger))
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
                        })]
                ));

        var applicationRuleCollections = ApplicationRuleCollections
            .Select(collection => new Core.ApplicationRuleCollection
            (
                name: collection.Name,
                priority: collection.Priority,
                action: Enum.Parse<Core.RuleAction>(collection.Action.Type),
                rules: collection.Rules
                    .Select(item => new Core.ApplicationRule
                    (
                        name: item.Name,
                        sourceIps: item.SourceIpGroups
                            .SelectMany(item => ipGroups[item].IpAddresses)
                            .Concat(item.SourceAddresses)
                            .Select(item => RuleIpRange.Parse(item, logger))
                            .Where(item => item is not null)
                            .Cast<RuleIpRange>()
                            .ToArray(),
                        destinationFqdns: item.TargetFqdns,
                        destinationTags: item.FqdnTags,
                        protocols: item.Protocols.Select(item => new Core.ApplicationProtocolPort(Protocol: Enum.Parse<Core.ApplicationProtocol>(item.ProtocolType), Port: item.Port)).ToArray()
                    )).ToArray())
            ).ToArray();

        return new Core.Firewall
        (
            NetworkRuleCollections: [.. networkRuleCollections],
            ApplicationRuleCollections: applicationRuleCollections
        );
    }
}