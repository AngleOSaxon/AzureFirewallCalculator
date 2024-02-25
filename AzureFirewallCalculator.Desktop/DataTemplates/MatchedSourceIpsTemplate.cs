namespace AzureFirewallCalculator.Desktop.DataTemplates;

public class MatchedSourceIpsTemplate : MatchedIpsTemplateBase
{
    public MatchedSourceIpsTemplate()
        : base(matchedIpsSelector: match => match.MatchedSourceIps, ruleIpsSelector: rule => rule.SourceIps)
    {

    }
}