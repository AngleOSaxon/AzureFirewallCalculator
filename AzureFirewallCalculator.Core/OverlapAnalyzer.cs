using System.Xml.Schema;
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
            if (rule == sourceRule)
            {
                continue;
            }
            
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

        var unmatchedRulePortions = new List<NetworkRule> { sourceRule };

        foreach (var overlap in matches)
        {
            var newUnmatchedPortions = new List<NetworkRule>();
            foreach (var unmatched in unmatchedRulePortions)
            {
                // I suspect someone with more knowledge of matrix math could produce a better and more rigorously defined solution
                // But I'm not that guy

                // This attempts to determine if any portion of the original rule is unhandled by the other rules.
                // It does so by progressively carving the original rule into smaller components by removing 
                // all the portions that are matched by a comparison rule.
                
                // We compare an unmatched rule segment to an overlap and find any components that are handled
                // and any components that are unhandled.  Each unhandled component is combined with the matched components
                // to create a new rule segment, so that we wind up with a collection of rules that combined form the inverse
                // of the overlap.
                // If there are any left by the time we've completed all comparisons, then it's only a partial match.  If
                // there are none, then it's a full match.

                var unmatchedSourceIps = GetIpNonOverlaps(unmatched.SourceIps, overlap.OverlappingSourceRanges);
                var matchedSourceIps = GetIpOverlaps(unmatched.SourceIps, overlap.OverlappingSourceRanges);
                var unmatchedDestinationIps = GetIpNonOverlaps(unmatched.DestinationIps, overlap.OverlappingDestinationRanges);
                var matchedDestinationIps = GetIpOverlaps(unmatched.DestinationIps, overlap.OverlappingDestinationRanges);
                var unmatchedDestinationPorts = GetPortNonOverlaps(unmatched.DestinationPorts, overlap.OverlappingPorts);
                var matchedDestinationPorts = GetPortOverlaps(unmatched.DestinationPorts, overlap.OverlappingPorts);
                var unmatchedProtocols = (unmatched.NetworkProtocols ^ overlap.OverlappingProtocols) & sourceRule.NetworkProtocols;
                var matchedProtocols = unmatched.NetworkProtocols & overlap.OverlappingProtocols;

                if (unmatchedSourceIps.Length != 0)
                {
                    newUnmatchedPortions.Add(unmatched with 
                    {
                        SourceIps = unmatchedSourceIps,
                        DestinationIps = matchedDestinationIps,
                        DestinationPorts = matchedDestinationPorts,
                        NetworkProtocols = matchedProtocols
                    });
                }
                
                if (unmatchedDestinationIps.Length != 0)
                {
                    newUnmatchedPortions.Add(unmatched with
                    {
                        SourceIps = matchedSourceIps,
                        DestinationIps = unmatchedDestinationIps,
                        DestinationPorts = matchedDestinationPorts,
                        NetworkProtocols = matchedProtocols
                    });
                }

                if (unmatchedDestinationPorts.Length != 0)
                {
                    newUnmatchedPortions.Add(unmatched with
                    {
                        SourceIps = matchedSourceIps,
                        DestinationIps = matchedDestinationIps,
                        DestinationPorts = unmatchedDestinationPorts,
                        NetworkProtocols = matchedProtocols
                    });
                }

                if (unmatchedProtocols != NetworkProtocols.None)
                {
                    newUnmatchedPortions.Add(unmatched with
                    {
                        SourceIps = matchedSourceIps,
                        DestinationIps = matchedDestinationIps,
                        DestinationPorts = matchedDestinationPorts,
                        NetworkProtocols = unmatchedProtocols
                    });
                }
            }
            unmatchedRulePortions = newUnmatchedPortions;
        }

        return unmatchedRulePortions.Any(item => item.DestinationIps.Length > 0 || item.SourceIps.Length > 0 || item.DestinationPorts.Length > 0 || item.NetworkProtocols != NetworkProtocols.None)
            ? OverlapType.Partial
            : OverlapType.Full;
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

    public static RuleIpRange[] GetIpNonOverlaps(IEnumerable<RuleIpRange> sourceRanges, IEnumerable<RuleIpRange> comparisonRanges)
    {
        var nonOverlappingRanges = new List<RuleIpRange>();
        static uint IncrementSafe(uint number) => number == uint.MaxValue ? number : number + 1;
        foreach (var sourceRange in sourceRanges)
        {
            var rangeStart = sourceRange.Start;
            bool totallyUnmatched = true;
            foreach (var comparisonRange in comparisonRanges)
            {
                // We're completely outside the comparison range
                if (sourceRange.Start > comparisonRange.End || sourceRange.End < comparisonRange.Start)
                {
                    continue;
                }

                totallyUnmatched = false;
                if (rangeStart < comparisonRange.Start)
                {
                    nonOverlappingRanges.Add(new (rangeStart, Math.Min(IncrementSafe(sourceRange.End), comparisonRange.Start - 1)));
                }
                rangeStart = Math.Max(rangeStart, comparisonRange.End);
            }
            if (rangeStart < sourceRange.End)
            {
                nonOverlappingRanges.Add(new (IncrementSafe(rangeStart), sourceRange.End));
            }
            if (totallyUnmatched)
            {
                nonOverlappingRanges.Add(sourceRange);
            }
        }
        return ConsolidateRanges(nonOverlappingRanges);
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

    public static RulePortRange[] GetPortNonOverlaps(IEnumerable<RulePortRange> sourceRanges, IEnumerable<RulePortRange> comparisonRanges)
    {
        var nonOverlappingRanges = new List<RulePortRange>();
        foreach (var sourceRange in nonOverlappingRanges)
        {
            var rangeStart = sourceRange.Start;
            foreach (var comparisonRange in comparisonRanges)
            {
                // We're completely outside the comparison range
                if (sourceRange.Start > comparisonRange.End || sourceRange.End < comparisonRange.Start)
                {
                    continue;
                }

                if (rangeStart < comparisonRange.Start)
                {
                    nonOverlappingRanges.Add(new (rangeStart, Math.Min(sourceRange.End, comparisonRange.Start)));
                }
                rangeStart = Math.Max(rangeStart, comparisonRange.End);
            }
            if (rangeStart < sourceRange.End)
            {
                nonOverlappingRanges.Add(new (rangeStart, sourceRange.End));
            }
        }
        return ConsolidateRanges(nonOverlappingRanges);
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