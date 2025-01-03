namespace AzureFirewallCalculator.Core;

public record struct ApplicationProtocolPort(ApplicationProtocol Protocol, ushort? Port)
{
    public override readonly string ToString() => $"{Protocol}:{Port?.ToString() ?? "*"}";
}

public record class Firewall(NetworkRuleCollection[] NetworkRuleCollections, ApplicationRuleCollection[] ApplicationRuleCollections, IpGroup[] IpGroups);

public record class IpGroup(string Name, RuleIpRange[] Ips);

public record class NetworkRuleMatch(bool Matched, RuleIpRange[] MatchedSourceIps, RuleIpRange[] MatchedDestinationIps, NetworkProtocols MatchedProtocols, RulePortRange[] MatchedPorts, NetworkRule Rule);

public record class ApplicationRuleMatch(bool Matched, RuleIpRange[] MatchedSourceIps, string[] MatchedTargetFqdns, ApplicationProtocolPort[] MatchedProtocolPorts, ApplicationRule Rule);

public abstract record class ProcessingResponseBase(int GroupPriority, int Priority, string CollectionName, RuleAction RuleAction);

public record class NetworkProcessingResponse(int GroupPriority, int Priority, string CollectionName, RuleAction RuleAction, NetworkRuleMatch[] MatchedRules) 
    : ProcessingResponseBase(GroupPriority, Priority, CollectionName, RuleAction);

public record class ApplicationProcessingResponse(int GroupPriority, int Priority, string CollectionName, RuleAction RuleAction, ApplicationRuleMatch[] MatchedRules) 
    : ProcessingResponseBase(GroupPriority, Priority, CollectionName, RuleAction);

public record class ServiceTag(string Name, string[] AddressPrefixes);

public record class IpSource(IpSourceType SourceType, string SourceName);

public record class IpGroupOverlap(OverlapType OverlapType, IpGroup OverlappingGroup, RuleIpRange[] OverlappingRanges);

public record class NetworkRuleOverlap(OverlapType OverlapType, NetworkRule OverlappingRule, RuleIpRange[] OverlappingSourceRanges, RuleIpRange[] OverlappingDestinationRanges, RulePortRange[] OverlappingPorts, NetworkProtocols OverlappingProtocols);

public record class OverlapSummary(NetworkRule SourceRule, OverlapType CumulativeOverlap, NetworkRuleOverlap[] Overlaps);