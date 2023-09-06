namespace AzureFirewallCalculator.Core;

public record class ApplicationRuleCollection
{
    public string Name { get; }

    public int Priority { get; }

    public RuleAction RuleAction { get; }

    public ApplicationRule[] Rules { get; }

    public ApplicationRuleCollection(string name, int priority, RuleAction action, ApplicationRule[] rules)
    {
        Name = name;
        Priority = priority;
        RuleAction = action;
        Rules = rules;
    }

    public ApplicationRuleMatch[] GetMatches(ApplicationRequest request) => Rules.Select(item => item.Matches(request)).Where(item => item.Matched).ToArray();
}