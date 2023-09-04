namespace AzureFirewallCalculator.Core;

public record struct ApplicationProtocolPort(ApplicationProtocol Protocol, ushort Port);

public record class Firewall(NetworkRuleCollection[] NetworkRuleCollections, ApplicationRuleCollection[] ApplicationRuleCollections);

public abstract record class ProcessingResponseBase(int Priority, string CollectionName, RuleAction RuleAction);

public record class NetworkProcessingResponse(int Priority, string CollectionName, RuleAction RuleAction, NetworkRule[] MatchedRules) : ProcessingResponseBase(Priority, CollectionName, RuleAction);

public record class ApplicationProcessingResponse(int Priority, string CollectionName, RuleAction RuleAction, ApplicationRule[] MatchedRules) : ProcessingResponseBase(Priority, CollectionName, RuleAction);