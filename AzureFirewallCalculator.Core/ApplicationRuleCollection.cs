namespace AzureFirewallCalculator.Core;

public record class ApplicationRuleCollection
{
    public string Name { get; }

    public int GroupPriority { get; set; }

    public int Priority { get; }

    public RuleAction RuleAction { get; }

    public ApplicationRule[] Rules { get; }

    public ApplicationRuleCollection(string name, int priority, RuleAction action, ApplicationRule[] rules)
    {
        Name = name;
        // Not clearly stated, but assuming ungrouped (ie, non-policy) rules are processed after any grouped rules
        // Though it's likely not possible grouped and ungrouped rules to coexist in the same firewall
        GroupPriority = int.MaxValue; 
        Priority = priority;
        RuleAction = action;
        Rules = rules;
    }

    public ApplicationRuleCollection(string name, int groupPriority, int priority, RuleAction action, ApplicationRule[] rules)
    {
        Name = name;
        GroupPriority = groupPriority;
        Priority = priority;
        RuleAction = action;
        Rules = rules;
    }

    public ApplicationRuleMatch[] GetMatches(IEnumerable<ApplicationRequest> requests) => Rules.Select(item => item.Matches(requests)).Where(item => item.Matched).ToArray();

    public ApplicationRuleMatch[] GetMatches(ApplicationRequest request) => Rules.Select(item => item.Matches(request)).Where(item => item.Matched).ToArray();
}