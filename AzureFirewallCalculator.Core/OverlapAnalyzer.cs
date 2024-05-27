using OneOf;
using OneOf.Types;

namespace AzureFirewallCalculator.Core;

public static class OverlapAnalyzer
{
    public static OverlapSummary CheckForOverlap(NetworkRule sourceRule, NetworkRule[] comparisonRules)
    {
        var matches = new List<Overlap>();
        foreach (var rule in comparisonRules)
        {
            var match = GetRuleOverlap(
                sourceRule: sourceRule,
                comparisonProtocols: rule.NetworkProtocols,
                comparisonSourceIpRanges: rule.SourceIps,
                comparisonDestinationIpRanges: rule.DestinationIps,
                comparisonPortRanges: rule.DestinationPorts
            );
            if (match.IsT0)
            {
                matches.Add(new Overlap(
                    OverlapType: match.AsT0.overlapType,
                    OverlappingRule: rule,
                    OverlappingSourceRanges: match.AsT0.sourceIpRanges,
                    OverlappingDestinationRanges: match.AsT0.destinationIpRanges,
                    OverlappingPorts: match.AsT0.destinationPortRange,
                    OverlappingProtocols: match.AsT0.protocols
                ));
            }
        }

        return new OverlapSummary(
            SourceRule: sourceRule,
            CumulativeOverlap: GetCumulativeOverlap(sourceRule, matches), // TODO: Replace with actual calculation of partial vs full
            Overlaps: [.. matches]
        );
    }

    public static OverlapType GetCumulativeOverlap(NetworkRule sourceRule, IEnumerable<Overlap> matches)
    {
        var overlapType = matches.Any() ? matches.Max(item => item.OverlapType) : OverlapType.None;
        if (overlapType == OverlapType.Full || overlapType == OverlapType.None)
        {
            return overlapType;
        }

        var consolidatedProtocols = matches.Aggregate(
            seed: NetworkProtocols.None,
            func: (protocols, overlap) => protocols | overlap.OverlappingProtocols
        );
        var consolidatedPorts = ConsolidateRanges(matches.SelectMany(item => item.OverlappingPorts)).OrderBy(item => item.Start).ThenBy(item => item.End);
        var consolidatedSourceIps = ConsolidateRanges(matches.SelectMany(item => item.OverlappingSourceRanges)).OrderBy(item => item.Start).ThenBy(item => item.End);
        var consolidatedDestinationIps = ConsolidateRanges(matches.SelectMany(item => item.OverlappingDestinationRanges)).OrderBy(item => item.Start).ThenBy(item => item.End);
 
        var match = GetRuleOverlap(
            sourceRule: sourceRule, 
            comparisonProtocols: consolidatedProtocols,
            comparisonSourceIpRanges: consolidatedSourceIps,
            comparisonDestinationIpRanges: consolidatedDestinationIps,
            comparisonPortRanges: consolidatedPorts
        );
        if (match.IsT1)
        {
            throw new Exception("No rule overlaps found, despite an OverlapType other than None.  This should not be possible");
        }
        return match.AsT0.overlapType;
    }

    public static RuleIpRange[] GetIpOverlaps(IEnumerable<RuleIpRange> sourceRanges, IEnumerable<RuleIpRange> comparisonRanges)
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
        return ConsolidateRanges(overlaps);
    }

    public static RulePortRange[] GetPortOverlaps(IEnumerable<RulePortRange> sourceRanges, IEnumerable<RulePortRange> comparisonRanges)
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
        return ConsolidateRanges(overlaps);
    }

    public static RulePortRange[] ConsolidateRanges(IEnumerable<RulePortRange> ranges)
    {
        if (ranges.Count() < 2)
        {
            return [.. ranges];
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

    public static RuleIpRange[] ConsolidateRanges(IEnumerable<RuleIpRange> ranges)
    {
        if (ranges.Count() < 2)
        {
            return [.. ranges];
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

    public static OneOfRuleOverlapResult GetRuleOverlap(
            NetworkRule sourceRule,
            NetworkProtocols comparisonProtocols,
            IEnumerable<RuleIpRange> comparisonSourceIpRanges,
            IEnumerable<RuleIpRange> comparisonDestinationIpRanges,
            IEnumerable<RulePortRange> comparisonPortRanges
        )
    {
        var protocolOverlap = comparisonProtocols & sourceRule.NetworkProtocols;
        if (protocolOverlap == NetworkProtocols.None)
        {
            return new None();
        }
        var isFullOverlap = sourceRule.NetworkProtocols == protocolOverlap;

        var portOverlap = GetPortOverlaps(sourceRule.DestinationPorts, comparisonPortRanges);
        if (portOverlap.Length == 0)
        {
            return new None();
        }
        isFullOverlap &= sourceRule.DestinationPorts.All(item => portOverlap.Any(overlap => overlap.Start <= item.Start && overlap.End >= item.End));

        var sourceIpOverlap = GetIpOverlaps(sourceRule.SourceIps, comparisonSourceIpRanges);
        if (sourceIpOverlap.Length == 0)
        {
            return new None();
        }
        isFullOverlap &= sourceRule.SourceIps.All(item => sourceIpOverlap.Any(overlap => overlap.Start <= item.Start && overlap.End >= item.End));

        var destinationIpOverlap = GetIpOverlaps(sourceRule.DestinationIps, comparisonDestinationIpRanges);
        if (destinationIpOverlap.Length == 0)
        {
            return new None();
        }
        isFullOverlap &= sourceRule.DestinationIps.All(item => destinationIpOverlap.Any(overlap => overlap.Start <= item.Start && overlap.End >= item.End));

        return (
            isFullOverlap ? OverlapType.Full : OverlapType.Partial,
            protocolOverlap,
            sourceIpOverlap,
            destinationIpOverlap,
            portOverlap
        );
    }
}

[GenerateOneOf]
public partial class OneOfRuleOverlapResult : OneOfBase<
    (OverlapType overlapType, NetworkProtocols protocols, RuleIpRange[] sourceIpRanges, RuleIpRange[] destinationIpRanges, RulePortRange[] destinationPortRange), 
    None
    > { }