using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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
            new RuleIpRange(new IpAddressBytes("10.0.0.0"), new IpAddressBytes("10.0.0.255")),
            new RuleIpRange(new IpAddressBytes("10.0.3.0"), new IpAddressBytes("10.0.127.255")),
            new RuleIpRange(new IpAddressBytes("10.0.0.128"), new IpAddressBytes("10.0.127.128")),
            new RuleIpRange(new IpAddressBytes("10.0.6.128"), new IpAddressBytes("10.0.7.128")),
            new RuleIpRange(new IpAddressBytes("10.0.7.0"), new IpAddressBytes("10.0.9.255")),
            new RuleIpRange(new IpAddressBytes("10.1.7.0"), new IpAddressBytes("10.1.9.255")),
        ];

        var foo = baseRanges.OrderBy(item => item.Start).Select(item => new IpRangeWithDepth(range: item, depth: 0, gap: false)).ToList();
        // Current state:
        // depth calc obviously broken; final range gets depth 2 instead of 0
        foreach (var current in foo)
        {
            foreach (var comparison in foo)
            {
                if (comparison == current)
                {
                    continue;
                }

                if (current.Range.Start > comparison.Range.Start && current.Range.Start <= comparison.Range.End)
                {
                    current.Depth = Math.Max(comparison.Depth + 1, current.Depth + 1);
                }
            }
        }
        IpRanges = foo;
    }

    public override void Render(DrawingContext context)
    {
        uint IncrementSafe(uint number) => number == uint.MaxValue ? uint.MaxValue : number + 1;
        uint DecrementSafe(uint number) => number == uint.MinValue ? uint.MinValue : number - 1;

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
                    gaps.Add(new (IncrementSafe(lastRangeEnd), DecrementSafe(range.Range.Start)));
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
                offset = Math.Round(IncrementSafe(range.Range.End) * ratio, maxPrecision) - distanceCovered;
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