namespace AzureFirewallCalculator.Core;

public record struct ApplicationProtocolPort(ApplicationProtocol Protocol, ushort? Port)
{
    public override readonly string ToString() => $"{Protocol}:{Port?.ToString() ?? "*"}";
}

public record class Firewall(NetworkRuleCollection[] NetworkRuleCollections, ApplicationRuleCollection[] ApplicationRuleCollections);

public record class NetworkRuleMatch(bool Matched, RuleIpRange[] MatchedSourceIps, RuleIpRange[] MatchedDestinationIps, NetworkProtocols MatchedProtocols, RulePortRange[] MatchedPorts, NetworkRule Rule);

public record class ApplicationRuleMatch(bool Matched, RuleIpRange[] MatchedSourceIps, string[] MatchedTargetFqdns, ApplicationProtocolPort[] MatchedProtocolPorts, ApplicationRule Rule);

public abstract record class ProcessingResponseBase(int Priority, string CollectionName, RuleAction RuleAction);

public record class NetworkProcessingResponse(int Priority, string CollectionName, RuleAction RuleAction, NetworkRuleMatch[] MatchedRules) 
    : ProcessingResponseBase(Priority, CollectionName, RuleAction);

public record class ApplicationProcessingResponse(int Priority, string CollectionName, RuleAction RuleAction, ApplicationRuleMatch[] MatchedRules) 
    : ProcessingResponseBase(Priority, CollectionName, RuleAction);

public record class ServiceTag(string Name, string[] AddressPrefixes);