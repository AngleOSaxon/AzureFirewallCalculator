using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Numerics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using AzureFirewallCalculator.Core;
using DynamicData;
using Microsoft.CodeAnalysis;
using Microsoft.Extensions.Logging;
using Splat;

namespace AzureFirewallCalculator.Desktop.Controls;

public partial class IpOverlapDisplay : UserControl
{
    private const double BaseRangeHeight = 10;
    private const double RangeHeightMultiplier = 1; // TODO: dynamically fetch based on text scaling?
    private const double RangeHeight = BaseRangeHeight * RangeHeightMultiplier;
    private const double VerticalMargin = 2;
    private const int MaxPrecision = 3;

    static IpOverlapDisplay()
    {
        AffectsMeasure<IpOverlapDisplay>(IpRangesProperty);
        AffectsMeasure<IpOverlapDisplay>(ComparisonRangesProperty);
    }

    public static readonly StyledProperty<RuleIpRange[]> IpRangesProperty = AvaloniaProperty.Register<IpOverlapDisplay, RuleIpRange[]>(nameof(IpRanges), defaultValue: []);
    public RuleIpRange[] IpRanges
    {
        get => GetValue(IpRangesProperty);
        set => SetValue(IpRangesProperty, value);
    }

    public static readonly StyledProperty<RuleIpRange[]> ComparisonRangesProperty = AvaloniaProperty.Register<IpOverlapDisplay, RuleIpRange[]>(nameof(ComparisonRanges), defaultValue: []);
    public RuleIpRange[] ComparisonRanges
    {
        get => GetValue(ComparisonRangesProperty);
        set => SetValue(ComparisonRangesProperty, value);
    }

    private DisplayableRange[] DisplayableRanges = [];

    private ILogger<IpOverlapDisplay> Logger { get; }

    public IpOverlapDisplay()
    {
        InitializeComponent();
        Logger = Locator.Current.GetRequiredService<ILoggerFactory>().CreateLogger<IpOverlapDisplay>();

        RuleIpRange[] baseRanges = [
            
        ];
        IpRanges = baseRanges;
        ComparisonRanges = baseRanges;
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        if (change.Property == IpRangesProperty && change.NewValue is RuleIpRange[] ranges)
        {
            DisplayableRanges = InitDisplayableRanges(ranges, ComparisonRanges);
        }
        else if (change.Property == ComparisonRangesProperty && change.NewValue is RuleIpRange[] comparisonRanges)
        {
            DisplayableRanges = InitDisplayableRanges(IpRanges, comparisonRanges);
        }
    }

    private DisplayableRange[] InitDisplayableRanges(RuleIpRange[] ranges, RuleIpRange[] comparisonRanges)
    {
        List<DisplayableRange> displayableRanges = [];
        var overlapsWithComparison = OverlapAnalyzer.GetIpOverlaps(sourceRanges: ranges, comparisonRanges: comparisonRanges, consolidate: true);
        foreach (var range in ranges)
        {
            if (overlapsWithComparison.Contains(range))
            {
                displayableRanges.Add(new DisplayableRange(range: range, depth: 0, gap: false, effectiveRange: new RuleIpRange(range.Start, range.End)));
            }
            else
            {
                var matchedOverlap = overlapsWithComparison.Where(overlap => range.Contains(overlap) || overlap.Contains(range));
                // No matches at all means we're not displayable
                if (!matchedOverlap.Any())
                {
                    continue;
                }

                foreach (var match in matchedOverlap)
                {
                    var lowerBound = Math.Max(match.Start, range.Start);
                    var upperBound = Math.Min(match.End, range.End);
                    displayableRanges.Add(new DisplayableRange(range: range, depth: 0, gap: false, effectiveRange: new RuleIpRange(lowerBound, upperBound)));
                }
            }
        }

        var overlapDisplayMapping = new List<(RuleIpRange overlap, List<DisplayableRange> overlappingRanges)>();

        foreach (var displayableRange in displayableRanges)
        {
            var overlaps = OverlapAnalyzer.GetIpOverlaps([displayableRange.EffectiveRange], displayableRanges.Where(item => item != displayableRange).Select(range => range.EffectiveRange), consolidate: false);
            var matching = overlaps.Select(overlap => (overlap: overlap, overlappingRanges: displayableRanges.Where(item => item.EffectiveRange.Contains(overlap)).ToList()));
            foreach (var (overlap, overlappingRanges) in matching)
            {
                var matched = overlapDisplayMapping.SingleOrDefault(item => item.overlap == overlap);
                if (matched == default)
                {
                    overlapDisplayMapping.Add((overlap, overlappingRanges));
                }
                else
                {
                    matched.overlappingRanges.AddRange(overlappingRanges.Except(matched.overlappingRanges));
                }
            }
        }

        // This seems to work, but I'm suspicious of it
        // Starts with a list of overlaps and the ranges involved, ordered by the Start of the overlap
        // Then we order the associated ranges by their Starts
        // Check to see if we have a Depth set already, so ranges that are involved in multiple overlaps
        // don't constantly lose their depth
        // Updates an ongoing bitmap of previously-seen depth values for this specific overlap, so we know
        // if we're stepping on another range
        // If depth hasn't been set yet, check if there's space already before any known depths
        // Else set depth to be after the latest known depth
        // It's 23:45 and I don't remember my thought process clearly; I think an aspect of the
        // ordering allows it to avoid issues where subsequent steps might move a properly-ordered
        // range forward to cover another range
        // I *think* it's that the earliest ranges get priority, so their depths win out, so therefore their
        // depths don't change--only the ones with later Start values, which won't be involved in an earlier overlap
        foreach (var (overlap, overlappingRanges) in overlapDisplayMapping)
        {
            var ordered = overlappingRanges.OrderBy(item => item.EffectiveRange.Start).ToList();
            // This could more easily and clearly be a hashset indicating known depths, but I wanted to play around
            // with bitmaps and this is a side project.  So there.
            uint knownDepths = 0;
            for (int index = 0; index < overlappingRanges.Count; index++)
            {
                uint relevantBit = 1U << ordered[index].Depth;
                var seenDepthBefore = knownDepths & relevantBit;
                if (ordered[index].Depth != default)
                {
                    if (seenDepthBefore != 0)
                    {
                        ordered[index].Depth = knownDepths == 0 ? 0 : BitOperations.Log2(knownDepths) + 1;
                    }
                }
                else
                {
                    var trailingZeros = BitOperations.TrailingZeroCount(knownDepths);
                    if (knownDepths != 0 && trailingZeros != 0)
                    {
                        ordered[index].Depth = trailingZeros - 1;
                    }
                    else
                    {
                        int mostSignificantPosition = knownDepths == 0 ? 0 : BitOperations.Log2(knownDepths) + 1;
                        ordered[index].Depth = Math.Max(index, mostSignificantPosition);
                    }
                }
                relevantBit = 1U << ordered[index].Depth;
                knownDepths |= relevantBit;
            }
        }

        return [.. displayableRanges];
    }

    protected override Size MeasureOverride(Size finalSize)
    {
        if (DisplayableRanges.Length == 0)
        {
            return base.MeasureOverride(finalSize);
        }

        var maxDepth = DisplayableRanges.Max(item => item.Depth);
        var maxHeight = maxDepth * RangeHeight + (VerticalMargin * maxDepth) + RangeHeight;

        var baseSize = base.MeasureOverride(finalSize);
        var updatedSize = baseSize.WithHeight(maxHeight);
        return updatedSize;
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        RangeDisplay.Children.Clear();

        // Basic goal: to arrange all IP ranges horizontally so that they're proportionate to each other
        // and to the comparison ranges in use.  This allows them to be compared by stacking the range displays
        // on top of each other vertically, making it visually easy to see which IPs are part of another rule.

        // To accomplish that, we start from the comparison ranges.  We have already produced a series
        // of DisplayableRanges by finding all the rule ranges that overlap with the comparison ranges, 
        // in some cases breaking a rule range into multiple ranges when it spans multiple comparison ranges.
        // We now take the comparison ranges and consolidate them to produce a set of range regions that we can draw.
        // We calculate their total length and their individual start/stop positions on the X-axis.
        // Then we go through them and find any of the Displayable rule ranges that are contained in the comparison range
        // for a drawable range region.
        // We position the Displayable range according to its EffectiveRange (ie, the range after it has been bounded
        // to fit inside the comparison range) inside the drawable region, working out the appropriate sizing ratio
        // to apply so that the resulting range positions will take up all available space inside the drawable range region but
        // not go beyond it.  Positions are then assigned to each EffectiveRange relative to the start point of the Canvas.
        // Once that is completed for all DisplayableRanges, we go through each one and apply the ratio for the total drawable
        // region and give them their final positions on the Canvas.

        // This prevents the drawn ranges from drifting due to inconsistencies in how minimum display sizes, gap sizes, 
        // and large numbers of rules are handled.  Particularly it ensures rules will display IPs in the same
        // position relative to other rules, so long as the control width is consistent.


        var controlWidth = finalSize.Width;

        var consolidatedComparisonRanges = OverlapAnalyzer.ConsolidateRanges(ComparisonRanges);
        var comparisonRangeGaps = CalculateGaps(consolidatedComparisonRanges);

        var numberOfGaps = comparisonRangeGaps.Count;
        // At most, this percent of control width should be used to show gaps
        var maxGapSize = 100d / Math.Max(numberOfGaps, 10);
        var minDisplaySize = 5d;

        var combinedConsolidatedComparisons = consolidatedComparisonRanges
            .Select(item => new DisplayableRange(range: item, depth: 0, gap: false, effectiveRange: new RuleIpRange(start: item.Start, end: item.End)))
            .Concat(comparisonRangeGaps)
            .OrderBy(item => item.EffectiveRange.Start);
        
        var distanceTravelled = 0d;
        List<(double startPosition, double endPosition, DisplayableRange range)> drawableRanges = new(combinedConsolidatedComparisons.Count());
        foreach (var consolidatedComparison in combinedConsolidatedComparisons)
        {
            var start = distanceTravelled;
            double length = consolidatedComparison.EffectiveRange.End - consolidatedComparison.EffectiveRange.Start;
            if (consolidatedComparison.Gap)
            {
                length = Math.Min(length, maxGapSize);
            }
            var end = start + Math.Max(length, minDisplaySize);
            distanceTravelled += end - start;

            drawableRanges.Add((start, end, consolidatedComparison));
        }

        var ratio = Math.Round(controlWidth / distanceTravelled, MaxPrecision);

        var orderedDisplayableRanges = DisplayableRanges.OrderBy(item => item.Range.Start);
        var positionedEffectiveRanges = new List<(double startPosition, double endPosition, DisplayableRange range)>();
        foreach (var (containerStart, containerEnd, comparisonRange) in drawableRanges)
        {
            var matchedRuleRanges = comparisonRange.Gap 
                ? [comparisonRange]
                : orderedDisplayableRanges.Where(ruleRange => comparisonRange.Range.Contains(ruleRange.EffectiveRange));

            // These ranges are assumed to not be additive in terms of distance travelled
            // They may overlap each other and therefore cannot be simply added together
            var maxDistanceTravelled = 0d;
            List<(double startPosition, double endPosition, DisplayableRange range)> internalRangePositions = new();
            foreach (var matchedRuleRange in matchedRuleRanges)
            {
                var start = matchedRuleRange.EffectiveRange.Start - comparisonRange.EffectiveRange.Start;
                double length = matchedRuleRange.EffectiveRange.End - matchedRuleRange.EffectiveRange.Start;
                if (matchedRuleRange.Gap)
                {
                    length = Math.Min(length, maxGapSize);
                }
                var end = start + Math.Max(length, minDisplaySize);
                internalRangePositions.Add((start, end, matchedRuleRange));

                maxDistanceTravelled = Math.Max(maxDistanceTravelled, end);
            }
            var internalRatio = Math.Round((containerEnd - containerStart) / maxDistanceTravelled, MaxPrecision);

            foreach (var (internalStartPosition, internalEndPosition, range) in internalRangePositions)
            {
                var adjustedStart = Math.Round(internalStartPosition * internalRatio, MaxPrecision);
                var adjustedEnd = Math.Round(internalEndPosition * internalRatio, MaxPrecision);
                positionedEffectiveRanges.Add((adjustedStart + containerStart, adjustedEnd + containerStart, range));
            }
        }

        var pen1 = new Pen(new SolidColorBrush(Color.FromRgb(r: 255, g: 0, b: 0)));
        var pen2 = new Pen(new SolidColorBrush(Color.FromRgb(r: 0, g: 255, b: 0)));
        var pen3 = new Pen(new SolidColorBrush(Color.FromRgb(r: 0, g: 0, b: 255)));
        var gapPen = new Pen(new SolidColorBrush(Color.FromRgb(r: 127, g: 127, b: 127), 0));
        int count = 0;
        foreach (var (startPosition, endPosition, range) in positionedEffectiveRanges)
        {
            var pen = range.Gap 
                ? gapPen 
                : (count++ % 3) switch
                    {
                        0 => pen1,
                        1 => pen2,
                        2 => pen3,
                        _ => pen1
                    };
            var heightStart = range.Depth * RangeHeight + (VerticalMargin * range.Depth);
            var adjustedStart = Math.Round(startPosition * ratio, MaxPrecision);
            var adjustedEnd = Math.Round(endPosition * ratio, MaxPrecision);

            if (adjustedEnd > controlWidth + 1)
            {
                Logger.LogTrace("Box end {boxEnd} is {boxOverrun} greater than {controlWidth} for range {range}", adjustedEnd, adjustedEnd - controlWidth, controlWidth, range);
            }

            var length = adjustedEnd - adjustedStart;
            IpRangeDisplay display = new()
            {
                Range = range.Range,
                IsGap = range.Gap,
                Pen = pen,
                EffectiveLowerBound = range.EffectiveRange.Start,
                EffectiveUpperBound = range.EffectiveRange.End,
                Height = RangeHeight,
                Width = length
            };
            Canvas.SetLeft(display, adjustedStart);
            Canvas.SetTop(display, heightStart);
            RangeDisplay.Children.Add(display);
        }

        var size = base.ArrangeOverride(finalSize);
        return size;
    }

    private static List<DisplayableRange> CalculateGaps(IEnumerable<RuleIpRange> ranges)
    {
        var gaps = new List<RuleIpRange>();
        var orderedIpRanges = ranges.OrderBy(item => item.Start).ToList();
        uint lastRangeEnd = orderedIpRanges?.FirstOrDefault().End ?? 0;
        foreach (var range in orderedIpRanges?.Skip(1) ?? [])
        {
            if (range.End > lastRangeEnd)
            {
                // Issue with abutting ranges; produces -1 sized gap
                if (range.Start - 1 > lastRangeEnd)
                {
                    gaps.Add(new (Utils.IncrementSafe(lastRangeEnd), Utils.DecrementSafe(range.Start)));
                }
                lastRangeEnd = range.End;
            }
        }

        return [ ..gaps.Select(item => new DisplayableRange(range: item, depth: 0, gap: true, effectiveRange: new RuleIpRange(start: item.Start, end: item.End))) ];
    }

    /// <summary>
    /// Contains the necessary information to display a range so that its overlaps with other
    /// IP ranges will be visible
    /// </summary>
    /// <param name="range">The IP range that will be displayed</param>
    /// <param name="depth">What depth the <paramref name="range"/> needs to appear at, to avoid being drawn on top of other ranges</param>
    /// <param name="gap">Whether this merely represents a gap between ranges</param>
    private class DisplayableRange(RuleIpRange range, int depth, bool gap, RuleIpRange effectiveRange)
    {
        public RuleIpRange Range { get; set; } = range;
        public int Depth { get; set; } = depth;
        public bool Gap { get; set; } = gap;
        public RuleIpRange EffectiveRange { get; } = effectiveRange;
    }
}