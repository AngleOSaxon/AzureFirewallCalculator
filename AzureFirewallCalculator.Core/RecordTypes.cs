namespace AzureFirewallCalculator.Core;

public record struct ApplicationProtocolPort(ApplicationProtocol Protocol, ushort Port);

public record class Firewall(NetworkRuleCollection[] NetworkRuleCollections, ApplicationRuleCollection[] ApplicationRuleCollections);

public record class NetworkRuleMatch(bool Matched, RuleIpRange[] MatchedSourceIps, RuleIpRange[] MatchedDestinationIps, NetworkRule Rule);

public record class ApplicationRuleMatch(bool Matched, RuleIpRange[] MatchedSourceIps, string[] MatchedTargetFqdns, ApplicationRule Rule);

public abstract record class ProcessingResponseBase(int Priority, string CollectionName, RuleAction RuleAction);

public record class NetworkProcessingResponse(int Priority, string CollectionName, RuleAction RuleAction, NetworkRuleMatch[] MatchedRules) 
    : ProcessingResponseBase(Priority, CollectionName, RuleAction);

public record class ApplicationProcessingResponse(int Priority, string CollectionName, RuleAction RuleAction, ApplicationRuleMatch[] MatchedRules) 
    : ProcessingResponseBase(Priority, CollectionName, RuleAction);