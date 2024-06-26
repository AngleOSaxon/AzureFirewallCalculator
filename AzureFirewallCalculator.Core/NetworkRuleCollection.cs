namespace AzureFirewallCalculator.Core;

public record class NetworkRuleCollection
{
    public string Name { get; }

    public int GroupPriority { get; set; }

    public int Priority { get; }

    public RuleAction RuleAction { get; }

    public NetworkRule[] Rules { get; }

    public NetworkRuleCollection(string name, int priority, RuleAction action, NetworkRule[] rules)
    {
        Name = name;
        GroupPriority = int.MaxValue;
        Priority = priority;
        RuleAction = action;
        Rules = rules;
    }

    public NetworkRuleCollection(string name, int groupPriority, int priority, RuleAction action, NetworkRule[] rules)
    {
        Name = name;
        GroupPriority = groupPriority;
        Priority = priority;
        RuleAction = action;
        Rules = rules;
    }

    public async Task<NetworkRuleMatch[]> GetMatches(NetworkRequest request) => (await Task.WhenAll(Rules.Select(item => item.Matches([request])))).Where(item => item.Matched).ToArray();

    public async Task<NetworkRuleMatch[]> GetMatches(IEnumerable<NetworkRequest> requests) => (await Task.WhenAll(Rules.Select(item => item.Matches(requests)))).Where(item => item.Matched).ToArray();
}