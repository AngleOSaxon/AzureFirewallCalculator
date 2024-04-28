using System.Text.Json.Serialization;
using OneOf;

namespace AzureFirewallCalculator.Core.PowershellSource;

public record struct IpGroup(string Id, string[] IpAddresses);

public record struct RuleAction(string Type);

public record class RuleCollectionGroup(string Name, RuleCollectionGroupProperties Properties);

public record class RuleCollectionGroupProperties(string Id, int Priority, RuleCollection[] RuleCollection);

public record class RuleCollection(string Name, int Priority, RuleAction Action, [property: JsonIgnore()] OneOf<NetworkRule[], ApplicationRule[]> Rules);

public record class NetworkRuleCollection(string Name, int Priority, RuleAction Action, NetworkRule[] Rules);

public record class ApplicationRuleCollection(string Name, int Priority, RuleAction Action, ApplicationRule[] Rules);

public record class NetworkRule(string Name, string[] SourceAddresses, string[] SourceIpGroups, string[] DestinationAddresses, string[] DestinationIpGroups, string[] DestinationFqdns, string[] DestinationPorts, string[] Protocols);

public record struct ApplicationProtocolPort(string ProtocolType, ushort Port);

public record class ApplicationRule(string Name, string[] SourceAddresses, string[] SourceIpGroups, string[] TargetFqdns, string[] FqdnTags, ApplicationProtocolPort[] Protocols);

public record class Policy(string Name, string Id, ResourceId[] RuleCollectionGroups);

public record class ResourceId(string Id);