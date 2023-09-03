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

    public NetworkRule[] GetMatches(NetworkRequest request) => Rules.Where(item => item.Matches(request)).ToArray();
}