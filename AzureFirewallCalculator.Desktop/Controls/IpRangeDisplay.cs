using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.TextFormatting.Unicode;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Desktop.Controls;

public class IpRangeDisplay : Control
{
    private List<IpRangeWithDepth> IpRanges { get; } = [];

    public IpRangeDisplay()
    {
        List<RuleIpRange> baseRanges = [
            new RuleIpRange(new IpAddressBytes("10.0.0.0"), new IpAddressBytes("10.0.0.255")), // r
            new RuleIpRange(new IpAddressBytes("10.0.3.0"), new IpAddressBytes("10.0.127.255")), // b
            new RuleIpRange(new IpAddressBytes("10.0.0.128"), new IpAddressBytes("10.0.127.128")), // g
            new RuleIpRange(new IpAddressBytes("10.0.6.128"), new IpAddressBytes("10.0.7.128")), // r
            new RuleIpRange(new IpAddressBytes("10.0.7.0"), new IpAddressBytes("10.0.9.255")), // g
            new RuleIpRange(new IpAddressBytes("10.1.7.0"), new IpAddressBytes("10.1.9.255")), // b
            new RuleIpRange(new IpAddressBytes("10.0.7.0"), new IpAddressBytes("10.0.11.127")), // g
            new RuleIpRange(new IpAddressBytes("10.0.10.0"), new IpAddressBytes("10.0.11.255")), // g
            new RuleIpRange(new IpAddressBytes("10.0.9.0"), new IpAddressBytes("10.0.11.255")),
            new RuleIpRange(new IpAddressBytes("10.0.9.1"), new IpAddressBytes("10.0.12.255"))
        ];

        var foo = baseRanges.OrderBy(item => item.Start).Select(item => new IpRangeWithDepth(range: item, depth: 0, gap: false)).ToList();

        var bar = new List<(RuleIpRange overlap, List<IpRangeWithDepth> ranges)>();

        for (int index = 0; index < foo.Count; index++)
        {
            var tst = foo[index].Range;
            var overlaps = OverlapAnalyzer.GetIpOverlaps([tst], foo.Where(item => item != foo[index]).Select(range => range.Range), consolidate: false);
            var matching = overlaps.Select(overlap => (overlap: overlap, ranges: foo.Where(item => item.Range.Contains(overlap)).ToList()));
            foreach (var (overlap, ranges) in matching)
            {
                var matched = bar.SingleOrDefault(item => item.overlap == overlap);
                if (matched == default)
                {
                    bar.Add((overlap, ranges));
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
        // It's 11:45 and I don't remember my thought process clearly; I think an aspect of the
        // ordering allows it to avoid issues where subsequent steps might move a properly-ordered
        // range forward to cover another range
        // I *think* it's that the earliest ranges get priority, so their depths win out, so therefore their
        // depths don't change--only the ones with later Start values, which won't be involved in an earlier overlap
        foreach (var (overlap, ranges) in bar)
        {
            var ordered = ranges.OrderBy(item => item.Range.Start).ToList();
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

        IpRanges = foo;
    }

    public override void Render(DrawingContext context)
    {
        // At most, this percent of control width should be used to show gaps
        const double maxGapPercentage = 0.1d;
        const double baseRangeHeight = 5;
        const double rangeHeightMultiplier = 1; // TODO: dynamically fetch based on text scaling?
        const double rangeHeight = baseRangeHeight * rangeHeightMultiplier;
        const double verticalMargin = 2;
        const int maxPrecision = 3;

        var controlWidth = Bounds.Width;
        var controlHeight = Math.Min(Bounds.Height, 50);

        var gaps = new List<RuleIpRange>();
        var orderedIpRanges = IpRanges.OrderBy(item => item.Range.Start).ToList();
        uint lastRangeEnd = orderedIpRanges.FirstOrDefault()?.Range.End ?? 0;
        foreach (var range in orderedIpRanges.Skip(1))
        {
            if (range.Range.End > lastRangeEnd)
            {
                if (range.Range.Start > lastRangeEnd)
                {
                    // Issue with abutting ranges; produces -1 sized gap
                    gaps.Add(new (Utils.IncrementSafe(lastRangeEnd), Utils.DecrementSafe(range.Range.Start)));
                }
                lastRangeEnd = range.Range.End;
            }
        }

        // Consolidate to avoid double-counting overlapping ranges
        var consolidatedRanges = OverlapAnalyzer.ConsolidateRanges(IpRanges.Select(item => item.Range));

        var maxGapSize = Math.Round(controlWidth * maxGapPercentage, maxPrecision);

        var consolidatedRangeLength = consolidatedRanges.Sum(item => Math.Max(item.End - item.Start, 1));
        var consolidatedGapLength = gaps.Sum(item => Math.Min(item.End - item.Start, maxGapSize));
        var totalRangeSize = consolidatedRangeLength + consolidatedGapLength;
        var ratio = Math.Round((controlWidth - consolidatedGapLength) / consolidatedRangeLength, maxPrecision);

        var pen1 = new Pen(new SolidColorBrush(Color.FromRgb(r: 255, g: 0, b: 0)));
        var pen2 = new Pen(new SolidColorBrush(Color.FromRgb(r: 0, g: 255, b: 0)));
        var pen3 = new Pen(new SolidColorBrush(Color.FromRgb(r: 0, g: 0, b: 255)));
        int count = 0;
        var ranges = orderedIpRanges.Concat(gaps.Select(item => new IpRangeWithDepth(range: item, gap: true, depth: 0))).OrderBy(item => item.Range.Start);

        double offset = Math.Round((ranges.FirstOrDefault()?.Range.Start ?? 0) * ratio, maxPrecision);
        var minDisplaySize = Math.Round(controlWidth / 100, maxPrecision);
        var distanceCovered = 0d;
        foreach (var range in ranges)
        {
            var boxStart = Math.Round(range.Range.Start * ratio, maxPrecision) - offset;
            var length = Math.Round((range.Range.End - range.Range.Start) * ratio, maxPrecision);
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
                offset = Math.Round(Utils.IncrementSafe(range.Range.End) * ratio, maxPrecision) - distanceCovered;
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
                var heightStart = range.Depth * rangeHeight + (verticalMargin * range.Depth);
                var rect = new Rect(topLeft: new Point(boxStart, heightStart), bottomRight: new Point(boxEnd, rangeHeight + heightStart));
                context.DrawRectangle(pen.Brush, pen, rect);
            }
        }
    }

    private class IpRangeWithDepth(RuleIpRange range, int depth, bool gap)
    {
        public RuleIpRange Range { get; set; } = range;
        public int Depth { get; set; } = depth;
        public bool Gap { get; set; } = gap;
    }

}