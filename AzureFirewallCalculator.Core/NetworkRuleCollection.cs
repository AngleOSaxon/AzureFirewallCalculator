namespace AzureFirewallCalculator.Core;

public record class NetworkRuleCollection
{
    public string Name { get; }

    public int Priority { get; }

    public RuleAction RuleAction { get; }

    public NetworkRule[] Rules { get; }

    public NetworkRuleCollection(string name, int priority, RuleAction action, NetworkRule[] rules)
    {
        Name = name;
        Priority = priority;
        RuleAction = action;
        Rules = rules;
    }

    public NetworkRuleMatch[] GetMatches(NetworkRequest request) => Rules.Select(item => item.Matches(request)).Where(item => item.Matched).ToArray();
}