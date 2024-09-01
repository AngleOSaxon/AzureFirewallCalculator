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
    }

    public static readonly StyledProperty<RuleIpRange[]> IpRangesProperty = AvaloniaProperty.Register<IpOverlapDisplay, RuleIpRange[]>(nameof(IpRanges), defaultValue: []);
    public RuleIpRange[] IpRanges
    {
        get => GetValue(IpRangesProperty);
        set => SetValue(IpRangesProperty, value);
    }

    public IpOverlapDisplay()
    {
        InitializeComponent();

        // List<RuleIpRange> baseRanges = [
        //     new RuleIpRange(new IpAddressBytes("10.0.0.0"), new IpAddressBytes("10.0.0.255")), // r
        //     new RuleIpRange(new IpAddressBytes("10.0.3.0"), new IpAddressBytes("10.0.127.255")), // b
        //     new RuleIpRange(new IpAddressBytes("10.0.0.128"), new IpAddressBytes("10.0.127.128")), // g
        //     new RuleIpRange(new IpAddressBytes("10.0.6.128"), new IpAddressBytes("10.0.7.128")), // r
        //     new RuleIpRange(new IpAddressBytes("10.0.7.0"), new IpAddressBytes("10.0.9.255")), // g
        //     new RuleIpRange(new IpAddressBytes("10.1.7.0"), new IpAddressBytes("10.1.9.255")), // b
        //     new RuleIpRange(new IpAddressBytes("10.0.7.0"), new IpAddressBytes("10.0.11.127")), // g
        //     new RuleIpRange(new IpAddressBytes("10.0.10.0"), new IpAddressBytes("10.0.11.255")), // g
        //     new RuleIpRange(new IpAddressBytes("10.0.9.0"), new IpAddressBytes("10.0.11.255")),
        //     new RuleIpRange(new IpAddressBytes("10.0.9.1"), new IpAddressBytes("10.0.12.255"))
        // ];

        

        // IpRanges.AddRange(baseRanges);
    }

    protected override Size MeasureOverride(Size finalSize)
    {
        var rangesWithDepth = CalculateRangeDepths(IpRanges);

        if (rangesWithDepth.Count == 0)
        {
            return base.MeasureOverride(finalSize);
        }

        var maxDepth = rangesWithDepth.Max(item => item.Depth);
        var maxHeight = maxDepth * RangeHeight + (VerticalMargin * maxDepth) + RangeHeight;

        var baseSize = base.MeasureOverride(finalSize);
        var updatedSize = baseSize.WithHeight(maxHeight);
        return updatedSize;
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        // Empty the list of controls.  Likely more efficient to keep and re-render them later
        // but one problem at a time.
        RangeDisplay.Children.Clear();

        var controlWidth = finalSize.Width;

        var rangesWithDepth = CalculateRangeDepths(IpRanges);
        var gaps = CalculateGaps(IpRanges);

        // TODO: Can pre-create the IpRangeDisplay objects without values, just count(IpRanges) + count(gaps)
        // Handle that when the IpRanges property updates and assign the values during arrange?  Maybe assign
        // the values early; don't need to redo all that every time someone resizes the window
        // Unclear how all this will work when dealing with virtualiation; problem for later

        // Consolidate to avoid double-counting overlapping ranges
        var consolidatedRanges = OverlapAnalyzer.ConsolidateRanges(IpRanges.Select(item => item));

        var numberOfGaps = gaps.Count;
        // At most, this percent of control width should be used to show gaps
        var maxGapPercentage = 1d / Math.Max(numberOfGaps, 10);
        var maxGapSize = Math.Round(controlWidth * maxGapPercentage, MaxPrecision);
        var minDisplaySize = Math.Round(controlWidth / 100d, MaxPrecision);

        var consolidatedRangeLength = consolidatedRanges.Sum(item => Math.Max(item.End - item.Start, minDisplaySize));
        var consolidatedGapLength = gaps.Sum(item => Math.Min(item.Range.End - item.Range.Start, maxGapSize));
        var totalRangeSize = consolidatedRangeLength + consolidatedGapLength;
        var ratio = Math.Round((controlWidth - consolidatedGapLength) / consolidatedRangeLength, MaxPrecision);

        var pen1 = new Pen(new SolidColorBrush(Color.FromRgb(r: 255, g: 0, b: 0)));
        var pen2 = new Pen(new SolidColorBrush(Color.FromRgb(r: 0, g: 255, b: 0)));
        var pen3 = new Pen(new SolidColorBrush(Color.FromRgb(r: 0, g: 0, b: 255)));
        int count = 0;
        
        var ranges = rangesWithDepth.Concat(gaps).OrderBy(item => item.Range.Start);

        double offset = Math.Round((ranges.FirstOrDefault()?.Range.Start ?? 0) * ratio, MaxPrecision);
        var distanceCovered = 0d;
        foreach (var range in ranges)
        {
            var boxStart = Math.Round(range.Range.Start * ratio, MaxPrecision) - offset;
            var length = Math.Round((range.Range.End - range.Range.Start) * ratio, MaxPrecision);
            if (length < minDisplaySize)
            {
                length = minDisplaySize;
            }
            var boxEnd = boxStart + length;

            if (range.Gap)
            {
                var gapLength = Math.Min(length, maxGapSize);
                distanceCovered += gapLength;
                // Adjust offset to place us at the farthest-right element + gapSize, so the next box knows where to start correctly
                // range end will be next range's start -1
                offset = Math.Round(Utils.IncrementSafe(range.Range.End) * ratio, MaxPrecision) - distanceCovered;
                // TODO: draw elision indicator
            }
            else
            {
                if (boxEnd > controlWidth)
                {
                    // TODO: Log?
                    Console.Error.WriteLine($"Warning: box end {boxEnd} is {boxEnd - controlWidth} greater than {controlWidth}");
                }

                distanceCovered = Math.Max(boxEnd, distanceCovered);
                var pen = (count++ % 3) switch
                {
                    0 => pen1,
                    1 => pen2,
                    2 => pen3,
                    _ => pen1
                };
                var heightStart = range.Depth * RangeHeight + (VerticalMargin * range.Depth);
                IpRangeDisplay display = new()
                {
                    Range = range.Range,
                    IsGap = range.Gap,
                    Pen = pen,
                    Height = RangeHeight,
                    Width = length,
                    MinWidth = length,
                };
                Canvas.SetLeft(display, boxStart);
                Canvas.SetTop(display, heightStart);
                RangeDisplay.Children.Add(display);
            }
        }

        var size = base.ArrangeOverride(finalSize);
        return size;
    }

    private static List<DisplayableRange> CalculateRangeDepths(IEnumerable<RuleIpRange> baseRanges)
    {
        var displayableRanges = baseRanges.OrderBy(item => item.Start).Select(item => new DisplayableRange(range: item, depth: 0, gap: false)).ToList();

        var overlapDisplayMapping = new List<(RuleIpRange overlap, List<DisplayableRange> ranges)>();

        for (int index = 0; index < displayableRanges.Count; index++)
        {
            var displayableRange = displayableRanges[index].Range;
            var overlaps = OverlapAnalyzer.GetIpOverlaps([displayableRange], displayableRanges.Where(item => item != displayableRanges[index]).Select(range => range.Range), consolidate: false);
            var matching = overlaps.Select(overlap => (overlap: overlap, ranges: displayableRanges.Where(item => item.Range.Contains(overlap)).ToList()));
            foreach (var (overlap, ranges) in matching)
            {
                var matched = overlapDisplayMapping.SingleOrDefault(item => item.overlap == overlap);
                if (matched == default)
                {
                    overlapDisplayMapping.Add((overlap, ranges));
                }
                else
                {
                    matched.ranges.AddRange(ranges.Except(matched.ranges));
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
        foreach (var (overlap, ranges) in overlapDisplayMapping)
        {
            var ordered = ranges.OrderBy(item => item.Range.Start).ToList();
            // This could more easily and clearly be a hashset indicating known depths, but I wanted to play around
            // with bitmaps and this is a side project.  So there.
            uint knownDepths = 0;
            for (int index = 0; index < ranges.Count; index++)
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

        return displayableRanges;
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

        return [ ..gaps.Select(item => new DisplayableRange(range: item, depth: 0, gap: true)) ];
    }

    /// <summary>
    /// Contains the necessary information to display a range so that its overlaps with other
    /// IP ranges will be visible
    /// </summary>
    /// <param name="range">The IP range that will be displayed</param>
    /// <param name="depth">What depth the <paramref name="range"/> needs to appear at, to avoid being drawn on top of other ranges</param>
    /// <param name="gap">Whether this merely represents a gap between ranges</param>
    private class DisplayableRange(RuleIpRange range, int depth, bool gap)
    {
        public RuleIpRange Range { get; set; } = range;
        public int Depth { get; set; } = depth;
        public bool Gap { get; set; } = gap;
    }

}