namespace AzureFirewallCalculator.Desktop.DataTemplates;

public class MatchedDestinationIpsTemplate : MatchedIpsTemplateBase
{
    public MatchedDestinationIpsTemplate()
        : base(matchedIpsSelector: match => match.MatchedDestinationIps, ruleIpsSelector: rule => rule.DestinationIps)
    {

    }
}