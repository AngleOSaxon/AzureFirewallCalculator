using AzureFirewallCalculator.Core.Dns;

namespace AzureFirewallCalculator.Core.PowershellSource;

public record struct Firewall
{
    public string Name { get; set; }

    public NetworkRuleCollection[] NetworkRuleCollections { get; set; }

    public ApplicationRuleCollection[] ApplicationRuleCollections { get; set; }

    public readonly Core.Firewall ConvertToFirewall(Dictionary<string, IpGroup> ipGroups, IDnsResolver resolver)
    {
        return new Core.Firewall
        (
            NetworkRuleCollections: NetworkRuleCollections
                .Select(collection => new Core.NetworkRuleCollection
                (
                    name: collection.Name,
                    priority: collection.Priority,
                    action: Enum.Parse<Core.RuleAction>(collection.Action.Type),
                    rules: collection.Rules
                        .Select(item => new Core.NetworkRule(
                            name: item.Name, 
                            sourceIps: item.SourceIpGroups
                                .SelectMany(item => ipGroups[item].IpAddresses)
                                .Concat(item.SourceAddresses)
                                .Select(item => RuleIpRange.Parse(item))
                                .Where(item => item is not null)
                                .Cast<RuleIpRange>()
                                .ToArray(), 
                            destinationIps: item.DestinationIpGroups
                                .SelectMany(item => ipGroups[item].IpAddresses)
                                .Concat(item.DestinationAddresses)
                                .Select(item => RuleIpRange.Parse(item))
                                .Where(item => item is not null)
                                .Cast<RuleIpRange>()
                                // TODO: Fix .Result usage.  Probably time to make a more typical imperative structure
                                .Concat(item.DestinationFqdns.Select(item => resolver.ResolveAddress(item).Result).SelectMany(item => item.Select(item => new RuleIpRange(start: item, end: item))))
                                .ToArray(),
                            destinationPorts: item.DestinationPorts
                                .Select(item => RulePortRange.Parse(item)!)
                                .Where(item => item is not null)
                                .Cast<RulePortRange>()
                                .ToArray(),
                            networkProtocols: Utils.ParseNetworkProtocols(item.Protocols)
                        ))
                        .ToArray()
                )).ToArray(),
            ApplicationRuleCollections: ApplicationRuleCollections
                .Select(collection => new Core.ApplicationRuleCollection
                (
                    name: collection.Name,
                    priority: collection.Priority,
                    action: Enum.Parse<Core.RuleAction>(collection.Action.Type),
                    rules: collection.Rules
                        .Select(item => new Core.ApplicationRule
                        (
                            name: item.Name,
                            sourceAddresses: item.SourceIpGroups
                                .SelectMany(item => ipGroups[item].IpAddresses)
                                .Concat(item.SourceAddresses)
                                .Select(item => RuleIpRange.Parse(item))
                                .Where(item => item is not null)
                                .Cast<RuleIpRange>()
                                .ToArray(),
                            destinationFqdns: item.TargetFqdns,
                            destinationTags: item.FqdnTags,
                            protocols: item.Protocols.Select(item => new Core.ApplicationProtocolPort(Protocol: Enum.Parse<Core.ApplicationProtocol>(item.ProtocolType), Port: item.Port)).ToArray()
                        )).ToArray())
                ).ToArray()
        );
    }
}