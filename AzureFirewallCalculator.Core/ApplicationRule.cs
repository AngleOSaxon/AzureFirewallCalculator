namespace AzureFirewallCalculator.Core;

public class ApplicationRule
{
    public string Name { get; }

    public RuleIpRange[] SourceAddresses { get; }

    public string[] DestinationFqdns { get; }

    public ReadOnlyMemory<char>[] PrefixWildcards { get; }

    public bool AllowAllDestinations { get; set; }

    public string[] DestinationTags { get; }

    public ApplicationProtocolPort[] Protocols { get; }

    public ApplicationRule(string name, RuleIpRange[] sourceAddresses, string[] destinationFqdns, string[] destinationTags, ApplicationProtocolPort[] protocols)
    {
        Name = name;
        SourceAddresses = sourceAddresses;

        var seed = (fqdns: new List<string>(), prefixWildcards: new List<ReadOnlyMemory<char>>(), allowAllDestinations: false);
        var (fqdns, prefixWildcards, allowAllDestinations) = destinationFqdns.Aggregate(seed, (accumulation, destinationFqdn) =>
        {
            var (fqdns, prefixWildcards, allowAllDestinations) = accumulation;

            // lower to skip casing issues
            destinationFqdn = destinationFqdn.ToLower();
            
            if (destinationFqdn == "*")
            {
                allowAllDestinations |= true;
            }
            else if (destinationFqdn[0] == '*')
            {
                prefixWildcards.Add(destinationFqdn.AsMemory(1));
            }
            else
            {
                fqdns.Add(destinationFqdn);
            }

            return (fqdns, prefixWildcards, allowAllDestinations);
        });

        DestinationFqdns = fqdns.ToArray();
        PrefixWildcards = prefixWildcards.ToArray();
        AllowAllDestinations = allowAllDestinations;

        DestinationTags = destinationTags;
        Protocols = protocols;
    }

    public ApplicationRuleMatch Matches(ApplicationRequest request)
    {
        var (sourceIp, destinationFqdn, protocol) = request;

        var sourceInRange = SourceAddresses.Where(item => sourceIp >= item.Start && sourceIp <= item.End);
        // TODO: Handle TargetURL postfix wildcards.  Only work in path; not in domain
        // https://learn.microsoft.com/en-us/azure/firewall/firewall-faq#how-do-wildcards-work-in-target-urls-and-target-fqdns-in-application-rules
        var destinationMatches = AllowAllDestinations
            ? DestinationFqdns
            : DestinationFqdns.Where(item => item.Equals(destinationFqdn));
        var protocolMatches = Protocols.Contains(protocol);

        return new ApplicationRuleMatch(
            Matched: sourceInRange.Any() && destinationMatches.Any() && protocolMatches,
            MatchedSourceIps: sourceInRange.ToArray(),
            MatchedTargetFqdns: destinationMatches.ToArray(),
            Rule: this
        );
    }
}