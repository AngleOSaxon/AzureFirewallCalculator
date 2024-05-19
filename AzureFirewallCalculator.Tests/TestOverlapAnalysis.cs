using System.Diagnostics.CodeAnalysis;
using System.Net;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Test;

namespace AzureFirewallCalculator.Tests;

public class TestOverlapAnalysis
{
    [Theory]
    [ClassData(typeof(OverlapAnalysisData))]
    public void TestNetworkRuleOverlapAnalysis(NetworkRule rule, NetworkRule[] comparisonRules, OverlapAnalyzer.OverlapSummary expectedOverlap)
    {
        var result = OverlapAnalyzer.CheckForOverlap(sourceRule: rule, comparisonRules: comparisonRules);
        AssertOverlapsMatch(expectedOverlap, result);
    }

    private readonly NetworkRule BaseRule = new("Test",
            sourceIps: [ new RuleIpRange() ],
            destinationIps: [ new RuleIpRange() ],
            destinationPorts: [ new RulePortRange() ],
            destinationFqdns: [],
            networkProtocols: NetworkProtocols.Any,
            dnsResolver: null!
        );

    
    [Theory]
    [InlineData(NetworkProtocols.Any, NetworkProtocols.TCP, NetworkProtocols.TCP, OverlapAnalyzer.OverlapType.Partial)]
    [InlineData(NetworkProtocols.Any, NetworkProtocols.UDP, NetworkProtocols.UDP, OverlapAnalyzer.OverlapType.Partial)]
    [InlineData(NetworkProtocols.Any, NetworkProtocols.ICMP, NetworkProtocols.ICMP, OverlapAnalyzer.OverlapType.Partial)]
    [InlineData(NetworkProtocols.TCP, NetworkProtocols.Any, NetworkProtocols.TCP, OverlapAnalyzer.OverlapType.Full)]
    [InlineData(NetworkProtocols.TCP, NetworkProtocols.TCP, NetworkProtocols.TCP, OverlapAnalyzer.OverlapType.Full)]
    [InlineData(NetworkProtocols.TCP | NetworkProtocols.UDP, NetworkProtocols.UDP, NetworkProtocols.UDP, OverlapAnalyzer.OverlapType.Partial)]
    [InlineData(NetworkProtocols.TCP, NetworkProtocols.TCP | NetworkProtocols.UDP, NetworkProtocols.TCP, OverlapAnalyzer.OverlapType.Full)]
    public void TestNetworkProtocolOverlaps_Match(NetworkProtocols sourceProtocols, NetworkProtocols comparisonProtocols, NetworkProtocols expectedMatch, OverlapAnalyzer.OverlapType expectedOverlapType)
    {
        var sourceRule = BaseRule with { NetworkProtocols = sourceProtocols };
        var comparisonRule = BaseRule with { NetworkProtocols = comparisonProtocols };

        var results = OverlapAnalyzer.CheckForOverlap(sourceRule, [comparisonRule]);
        Assert.Equal(expectedMatch, results.Overlaps[0].OverlappingProtocols);
        Assert.Equal(expectedOverlapType, results.Overlaps[0].OverlapType);
    }

    [Theory]
    [InlineData(NetworkProtocols.UDP, NetworkProtocols.TCP)]
    [InlineData(NetworkProtocols.Any, NetworkProtocols.None)]
    [InlineData(NetworkProtocols.TCP, NetworkProtocols.ICMP)]
    [InlineData(NetworkProtocols.UDP, NetworkProtocols.ICMP)]
    [InlineData(NetworkProtocols.ICMP, NetworkProtocols.TCP | NetworkProtocols.UDP)]
    [InlineData(NetworkProtocols.TCP | NetworkProtocols.UDP, NetworkProtocols.ICMP)]
    public void TestNetworkProtocolOverlaps_NoMatch(NetworkProtocols sourceProtocols, NetworkProtocols comparisonProtocols)
    {
        var sourceRule = BaseRule with { NetworkProtocols = sourceProtocols };
        var comparisonRule = BaseRule with { NetworkProtocols = comparisonProtocols };

        var results = OverlapAnalyzer.CheckForOverlap(sourceRule, [comparisonRule]);

        Assert.Empty(results.Overlaps);
    }

    public static IEnumerable<object[]> NetworkPortOverlaps()
    {
        yield return new object[]
        {
            new RulePortRange[] { new(55, 55) },
            new RulePortRange[] { new(50, 100) },
            new RulePortRange[] { new(55, 55) },
            OverlapAnalyzer.OverlapType.Full
        };
        yield return new object[]
        {
            new RulePortRange[] { new(50, 100) },
            new RulePortRange[] { new(55, 55) },
            new RulePortRange[] { new(55, 55) },
            OverlapAnalyzer.OverlapType.Partial
        };
        yield return new object[]
        {
            new RulePortRange[] { new(50, 100) },
            new RulePortRange[] { new(55, 55), new(40, 52) },
            new RulePortRange[] { new(55, 55), new(50, 52) },
            OverlapAnalyzer.OverlapType.Partial
        };
        yield return new object[]
        {
            new RulePortRange[] { new(50, 100) },
            new RulePortRange[] { new(40, 55), new(90, 125) },
            new RulePortRange[] { new(50, 55), new(90, 100) },
            OverlapAnalyzer.OverlapType.Partial
        };
        yield return new object[]
        {
            new RulePortRange[] { new(50, 100) },
            new RulePortRange[] { new(40, 75), new(75, 125) },
            new RulePortRange[] { new(50, 100) },
            OverlapAnalyzer.OverlapType.Full
        };
        yield return new object[]
        {
            new RulePortRange[] { new(55, 55), new(56, 56) },
            new RulePortRange[] { new(50, 100) },
            new RulePortRange[] { new(55, 56) },
            OverlapAnalyzer.OverlapType.Full
        };
        yield return new object[]
        {
            new RulePortRange[] { new(55, 55), new(56, 56) },
            new RulePortRange[] { new(ushort.MinValue, ushort.MaxValue), new(50, 60) },
            new RulePortRange[] { new(55, 56) },
            OverlapAnalyzer.OverlapType.Full
        };
    }

    [Theory]
    [MemberData(nameof(NetworkPortOverlaps))]
    public void TestNetworkPortOverlaps_Match(RulePortRange[] sourcePorts, RulePortRange[] comparisonPorts, RulePortRange[] expectedMatch, OverlapAnalyzer.OverlapType expectedOverlapType)
    {
        var sourceRule = BaseRule with { DestinationPorts = sourcePorts };
        var comparisonRule = BaseRule with { DestinationPorts = comparisonPorts };
        var results = OverlapAnalyzer.CheckForOverlap(sourceRule, [comparisonRule]);

        var baseOverlapSummary = new OverlapAnalyzer.OverlapSummary(BaseRule, OverlapAnalyzer.OverlapType.Partial, []);
        var baseOverlap = new OverlapAnalyzer.Overlap(OverlapAnalyzer.OverlapType.Full, BaseRule, [new()], [new()], [new()], NetworkProtocols.Any);
        OverlapAnalyzer.Overlap[] expected = [baseOverlap with { OverlapType = expectedOverlapType, OverlappingRule = comparisonRule, OverlappingPorts = expectedMatch }];

        Assert.True(expected.ElementByElementCompare(results.Overlaps, OverlapEquals));
    }

    public static IEnumerable<object[]> NetworkPortNoOverlap()
    {
        yield return new object[]
        {
            new RulePortRange[] { new(25, 35) },
            new RulePortRange[] { new(50, 100) }
        };
        yield return new object[]
        {
            new RulePortRange[] { new(50, 50), new(75, 80) },
            new RulePortRange[] { new(55, 55) }
        };
        yield return new object[]
        {
            new RulePortRange[] { new(50, 50), new(30, 39) },
            new RulePortRange[] { new(55, 55), new(40, 49) }
        };
    }

    [Theory]
    [MemberData(nameof(NetworkPortNoOverlap))]
    public void TestNetworkPortOverlaps_NoMatch(RulePortRange[] sourcePorts, RulePortRange[] comparisonPorts)
    {
        var sourceRule = BaseRule with { DestinationPorts = sourcePorts };
        var comparisonRule = BaseRule with { DestinationPorts = comparisonPorts };
        var results = OverlapAnalyzer.CheckForOverlap(sourceRule, [comparisonRule]);

        Assert.Empty(results.Overlaps);
    }

    private static void AssertOverlapsMatch(OverlapAnalyzer.OverlapSummary expected, OverlapAnalyzer.OverlapSummary actual)
    {
        Assert.Equal(expected.CumulativeOverlap, actual.CumulativeOverlap);
        Assert.Equal(expected.SourceRule, expected.SourceRule);
        Assert.Equal(expected.Overlaps.Length, actual.Overlaps.Length);
        Assert.True(expected.Overlaps.ElementByElementCompare(actual.Overlaps, OverlapEquals));
    }

    private static bool OverlapEquals(OverlapAnalyzer.Overlap? x, OverlapAnalyzer.Overlap? y)
    {
        return (x?.OverlapType == y?.OverlapType)
            && (x?.OverlappingRule.Equals(y?.OverlappingRule) ?? false)
            && (x?.OverlappingSourceRanges.OrderBy(item => item.Start).ElementByElementCompare(y.OverlappingSourceRanges.OrderBy(item => item.Start)) ?? false)
            && (x?.OverlappingDestinationRanges.OrderBy(item => item.Start).ElementByElementCompare(y.OverlappingDestinationRanges.OrderBy(item => item.Start)) ?? false)
            && (x?.OverlappingPorts.OrderBy(item => item.Start).ElementByElementCompare(y.OverlappingPorts.OrderBy(item => item.Start)) ?? false)
            && (x?.OverlappingProtocols.Equals(y?.OverlappingProtocols) ?? false);
    }
}