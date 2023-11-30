namespace AzureFirewallCalculator.Core;

public record class ApplicationRule
{
    public string Name { get; }

    public RuleIpRange[] SourceIps { get; }

    public string[] DestinationFqdns { get; }

    public string[] PrefixWildcards { get; }

    public bool AllowAllDestinations { get; set; }

    public string[] DestinationTags { get; }

    public ApplicationProtocolPort[] Protocols { get; }

    public ApplicationRule(string name, RuleIpRange[] sourceIps, string[] destinationFqdns, string[] destinationTags, ApplicationProtocolPort[] protocols)
    {
        Name = name;
        SourceIps = sourceIps;

        var seed = (fqdns: new List<string>(), prefixWildcards: new List<string>(), allowAllDestinations: false);
        var (fqdns, prefixWildcards, allowAllDestinations) = destinationFqdns.Aggregate(seed, (accumulation, destinationFqdn) =>
        {
            var (fqdns, prefixWildcards, allowAllDestinations) = accumulation;

            // lower to skip casing issues
            destinationFqdn = destinationFqdn.ToLower();
            
            if (destinationFqdn == "*")
            {
                allowAllDestinations |= true;
                fqdns.Add(destinationFqdn);
            }
            else if (destinationFqdn[0] == '*')
            {
                prefixWildcards.Add(destinationFqdn);
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

        var sourceInRange = sourceIp == null
            ? SourceIps
            : SourceIps.Where(item => sourceIp >= item.Start && sourceIp <= item.End);
        // TODO: Handle TargetURL postfix wildcards.  Only work in path; not in domain
        // https://learn.microsoft.com/en-us/azure/firewall/firewall-faq#how-do-wildcards-work-in-target-urls-and-target-fqdns-in-application-rules

        var destinationMatches = destinationFqdn == "*"
            ? DestinationFqdns.Concat(PrefixWildcards)
            : DestinationFqdns
                .Where(item => item.Equals(destinationFqdn))
                .Concat(PrefixWildcards
                    .Where(item => item.Length - 1 <= destinationFqdn.Length && item.AsSpan(1).SequenceEqual(destinationFqdn.AsSpan(destinationFqdn.Length - item.Length + 1, item.Length - 1))));

        if (AllowAllDestinations)
        {
            destinationMatches = destinationMatches.Concat(new string[] { "*" });
        }

        var protocolMatches = Protocols.FirstOrDefault(item => item.Protocol == protocol.Protocol && (item.Port == protocol.Port || protocol.Port == null));

        return new ApplicationRuleMatch(
            Matched: sourceInRange.Any() && destinationMatches.Any() && protocolMatches != default,
            MatchedSourceIps: sourceInRange.ToArray(),
            MatchedTargetFqdns: destinationMatches.ToArray(),
            MatchedProtocolPorts: [protocolMatches],
            Rule: this
        );
    }
}