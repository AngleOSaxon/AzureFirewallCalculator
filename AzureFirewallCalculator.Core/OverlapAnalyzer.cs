namespace AzureFirewallCalculator.Core;

public static class OverlapAnalyzer
{
    public enum OverlapType
    {
        None,
        Partial,
        Full
    }

    public record Overlap(OverlapType OverlapType, NetworkRule OverlappingRule, RuleIpRange[] OverlappingSourceRanges, RuleIpRange[] OverlappingDestinationRanges, RulePortRange[] OverlappingPorts, NetworkProtocols OverlappingProtocols);

    public record OverlapSummary(NetworkRule SourceRule, OverlapType CumulativeOverlap, Overlap[] Overlaps);

    public static OverlapSummary CheckForOverlap(NetworkRule sourceRule, NetworkRule[] comparisonRules)
    {
        var matches = new List<Overlap>();
        foreach (var rule in comparisonRules)
        {
            var protocolOverlap = rule.NetworkProtocols & sourceRule.NetworkProtocols;
            if (protocolOverlap == NetworkProtocols.None)
            {
                continue;
            }
            var isFullOverlap = sourceRule.NetworkProtocols == protocolOverlap;

            var portOverlap = GetPortOverlaps(sourceRule.DestinationPorts, rule.DestinationPorts);
            if (portOverlap.Length == 0)
            {
                continue;
            }
            portOverlap = ConsolidateRanges(portOverlap);
            isFullOverlap &= sourceRule.DestinationPorts.All(item => portOverlap.Any(overlap => overlap.Start <= item.Start && overlap.End >= item.End));

            var sourceIpOverlap = GetIpOverlaps(sourceRule.SourceIps, rule.SourceIps);
            if (sourceIpOverlap.Length == 0)
            {
                continue;
            }
            isFullOverlap &= sourceRule.SourceIps.All(item => sourceIpOverlap.Any(overlap => overlap.Start <= item.Start && overlap.End >= item.End));

            var destinationIpOverlap = GetIpOverlaps(sourceRule.DestinationIps, rule.DestinationIps);
            if (destinationIpOverlap.Length == 0)
            {
                continue;
            }
            isFullOverlap &= sourceRule.DestinationIps.All(item => destinationIpOverlap.Any(overlap => overlap.Start <= item.Start && overlap.End >= item.End));

            matches.Add(new Overlap(
                OverlapType: isFullOverlap ? OverlapType.Full : OverlapType.Partial,
                OverlappingRule: rule,
                OverlappingSourceRanges: sourceIpOverlap,
                OverlappingDestinationRanges: destinationIpOverlap,
                OverlappingPorts: portOverlap,
                OverlappingProtocols: protocolOverlap
            ));
        }

        return new OverlapSummary(
            SourceRule: sourceRule,
            CumulativeOverlap: matches.Count != 0 ? OverlapType.Partial : OverlapType.None, // TODO: Replace with actual calculation of partial vs full
            Overlaps: [.. matches]
        );
    }

    public static RuleIpRange[] GetIpOverlaps(RuleIpRange[] sourceRanges, RuleIpRange[] comparisonRanges)
    {
        var overlaps = new List<RuleIpRange>();
        foreach (var sourceRange in sourceRanges)
        {
            foreach (var comparisonRange in comparisonRanges)
            {
                if (sourceRange.Start <= comparisonRange.End && sourceRange.End >= comparisonRange.Start)
                {
                    var start = Math.Max(sourceRange.Start, comparisonRange.Start);
                    var end = Math.Min(sourceRange.End, comparisonRange.End);
                    overlaps.Add(new RuleIpRange(start, end));
                }
            }
        }
        return [.. overlaps];
    }

    public static RulePortRange[] GetPortOverlaps(RulePortRange[] sourceRanges, RulePortRange[] comparisonRanges)
    {
        var overlaps = new List<RulePortRange>();
        foreach (var sourceRange in sourceRanges)
        {
            foreach (var comparisonRange in comparisonRanges)
            {
                if (sourceRange.Start <= comparisonRange.End && sourceRange.End >= comparisonRange.Start)
                {
                    var start = Math.Max(sourceRange.Start, comparisonRange.Start);
                    var end = Math.Min(sourceRange.End, comparisonRange.End);
                    overlaps.Add(new RulePortRange(start, end));
                }
            }
        }
        return [.. overlaps];
    }

    public static RulePortRange[] ConsolidateRanges(RulePortRange[] ranges)
    {
        if (ranges.Length < 2)
        {
            return ranges;
        }

        var result = ranges.OrderBy(item => item.Start).Aggregate(new List<RulePortRange>(), (seed, range) =>
        {
            if (seed.Count == 0)
            {
                seed.Add(range);
                return seed;
            }

            var prevRange = seed.Last();
            if (range.Start <= (prevRange.End + 1) && range.End >= prevRange.End)
            {
                seed.Remove(prevRange);
                seed.Add(new(prevRange.Start, range.End));
            }
            else
            {
                seed.Add(range);
            }
            return seed;
        });
        return [..result];
    }

    public static RuleIpRange[] ConsolidateRanges(RuleIpRange[] ranges)
    {
        if (ranges.Length < 2)
        {
            return ranges;
        }

        var result = ranges.OrderBy(item => item.Start).Aggregate(new List<RuleIpRange>(), (seed, range) =>
        {
            if (seed.Count == 0)
            {
                seed.Add(range);
                return seed;
            }

            var prevRange = seed.Last();
            if (range.Start <= (prevRange.End + 1) && range.End >= prevRange.End)
            {
                seed.Remove(prevRange);
                seed.Add(new(prevRange.Start, range.End));
            }
            else
            {
                seed.Add(range);
            }
            return seed;
        });
        return [..result];
    }
}