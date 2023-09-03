namespace AzureFirewallCalculator.Core;

public class ApplicationRule
{
    public string Name { get; }

    public RuleIpRange[] SourceAddresses { get; }

    public string[] DestinationFqdns { get; }

    public string[] DestinationTags { get; }

    public ApplicationProtocolPort[] Protocols { get; }

    public ApplicationRule(string name, RuleIpRange[] sourceAddresses, string[] destinationFqdns, string[] destinationTags, ApplicationProtocolPort[] protocols)
    {
        Name = name;
        SourceAddresses = sourceAddresses;
        DestinationFqdns = destinationFqdns;
        DestinationTags = destinationTags;
        Protocols = protocols;
    }

    public bool Matches(ApplicationRequest request)
    {
        var (sourceIp, destinationFqdn, protocol) = request;

        var sourceInRange = SourceAddresses.Any(item => sourceIp >= item.Start && sourceIp <= item.End);
        // TODO: Handle wildcard rules
        // https://learn.microsoft.com/en-us/azure/firewall/firewall-faq#how-do-wildcards-work-in-target-urls-and-target-fqdns-in-application-rules
        var destinationMatches = DestinationFqdns.Any(item => item.Equals(destinationFqdn, StringComparison.CurrentCultureIgnoreCase));
        var protocolMatches = Protocols.Contains(protocol);

        return sourceInRange && destinationMatches && protocolMatches;
    }
}