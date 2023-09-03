namespace AzureFirewallCalculator.Core.PowershellSource;

public record struct IpGroup(string Id, string[] IpAddresses);

public record struct RuleAction(string Type);

public record struct NetworkRuleCollection(string Name, int Priority, RuleAction Action, NetworkRule[] Rules);

public record struct NetworkRule(string Name, string[] SourceAddresses, string[] SourceIpGroups, string[] DestinationAddresses, string[] DestinationIpGroups, string[] DestinationFqdns, string[] DestinationPorts, string[] Protocols);

public record struct ApplicationRuleCollection(string Name, int Priority, RuleAction Action, ApplicationRule[] Rules);

public record struct ApplicationProtocolPort(string ProtocolType, ushort Port);

public record struct ApplicationRule(string Name, string[] SourceAddresses, string[] SourceIpGroups, string[] TargetFqdns, string[] FqdnTags, ApplicationProtocolPort[] Protocols);