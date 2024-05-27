using System.Diagnostics.CodeAnalysis;
using System.Net;
using Azure.ResourceManager.Network;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Test;

namespace AzureFirewallCalculator.Tests;

public class TestOverlapAnalysis
{
    [Theory]
    [ClassData(typeof(OverlapAnalysisData))]
    public void TestNetworkRuleOverlapAnalysis(NetworkRule rule, NetworkRule[] comparisonRules, OverlapSummary expectedOverlap)
    {
        var result = OverlapAnalyzer.CheckForOverlap(sourceRule: rule, comparisonRules: comparisonRules);
        AssertOverlapsMatch(expectedOverlap, result);
    }

    private static readonly NetworkRule BaseRule = new("Test",
            sourceIps: [ new RuleIpRange() ],
            destinationIps: [ new RuleIpRange() ],
            destinationPorts: [ new RulePortRange() ],
            destinationFqdns: [],
            networkProtocols: NetworkProtocols.Any,
            dnsResolver: null!
        );

    private static readonly Overlap BaseOverlap = new(
        OverlapType: OverlapType.Partial,
        OverlappingRule: BaseRule,
        OverlappingSourceRanges: [ new RuleIpRange() ],
        OverlappingDestinationRanges: [ new RuleIpRange() ],
        OverlappingPorts: [ new RulePortRange() ],
        OverlappingProtocols: NetworkProtocols.None
    );
    
    [Theory]
    [InlineData(NetworkProtocols.Any, NetworkProtocols.TCP, NetworkProtocols.TCP, OverlapType.Partial)]
    [InlineData(NetworkProtocols.Any, NetworkProtocols.UDP, NetworkProtocols.UDP, OverlapType.Partial)]
    [InlineData(NetworkProtocols.Any, NetworkProtocols.ICMP, NetworkProtocols.ICMP, OverlapType.Partial)]
    [InlineData(NetworkProtocols.TCP, NetworkProtocols.Any, NetworkProtocols.TCP, OverlapType.Full)]
    [InlineData(NetworkProtocols.TCP, NetworkProtocols.TCP, NetworkProtocols.TCP, OverlapType.Full)]
    [InlineData(NetworkProtocols.TCP | NetworkProtocols.UDP, NetworkProtocols.UDP, NetworkProtocols.UDP, OverlapType.Partial)]
    [InlineData(NetworkProtocols.TCP, NetworkProtocols.TCP | NetworkProtocols.UDP, NetworkProtocols.TCP, OverlapType.Full)]
    public void TestNetworkProtocolOverlaps_Match(NetworkProtocols sourceProtocols, NetworkProtocols comparisonProtocols, NetworkProtocols expectedMatch, OverlapType expectedOverlapType)
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
            OverlapType.Full
        };
        yield return new object[]
        {
            new RulePortRange[] { new(50, 100) },
            new RulePortRange[] { new(55, 55) },
            new RulePortRange[] { new(55, 55) },
            OverlapType.Partial
        };
        yield return new object[]
        {
            new RulePortRange[] { new(50, 100) },
            new RulePortRange[] { new(55, 55), new(40, 52) },
            new RulePortRange[] { new(55, 55), new(50, 52) },
            OverlapType.Partial
        };
        yield return new object[]
        {
            new RulePortRange[] { new(50, 100) },
            new RulePortRange[] { new(40, 55), new(90, 125) },
            new RulePortRange[] { new(50, 55), new(90, 100) },
            OverlapType.Partial
        };
        yield return new object[]
        {
            new RulePortRange[] { new(50, 100) },
            new RulePortRange[] { new(40, 75), new(75, 125) },
            new RulePortRange[] { new(50, 100) },
            OverlapType.Full
        };
        yield return new object[]
        {
            new RulePortRange[] { new(55, 55), new(56, 56) },
            new RulePortRange[] { new(50, 100) },
            new RulePortRange[] { new(55, 56) },
            OverlapType.Full
        };
        yield return new object[]
        {
            new RulePortRange[] { new(55, 55), new(56, 56) },
            new RulePortRange[] { new(ushort.MinValue, ushort.MaxValue), new(50, 60) },
            new RulePortRange[] { new(55, 56) },
            OverlapType.Full
        };
    }

    [Theory]
    [MemberData(nameof(NetworkPortOverlaps))]
    public void TestNetworkPortOverlaps_Match(RulePortRange[] sourcePorts, RulePortRange[] comparisonPorts, RulePortRange[] expectedMatch, OverlapType expectedOverlapType)
    {
        var sourceRule = BaseRule with { DestinationPorts = sourcePorts };
        var comparisonRule = BaseRule with { DestinationPorts = comparisonPorts };
        var results = OverlapAnalyzer.CheckForOverlap(sourceRule, [comparisonRule]);

        var baseOverlapSummary = new OverlapSummary(BaseRule, OverlapType.Partial, []);
        var baseOverlap = new Overlap(OverlapType.Full, BaseRule, [new()], [new()], [new()], NetworkProtocols.Any);
        Overlap[] expected = [baseOverlap with { OverlapType = expectedOverlapType, OverlappingRule = comparisonRule, OverlappingPorts = expectedMatch }];

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

    public static IEnumerable<object[]> IpOverlaps()
    {
        yield return new object[]
        {
            new RuleIpRange[] { new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.0.0").ConvertToUint()) },
            new RuleIpRange[] { new(IPAddress.Parse("9.0.0.0").ConvertToUint(), IPAddress.Parse("11.0.0.0").ConvertToUint()) },
            new RuleIpRange[] { new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.0.0").ConvertToUint()) },
            OverlapType.Full
        };
        yield return new object[]
        {
            new RuleIpRange[] { new(IPAddress.Parse("9.0.0.0").ConvertToUint(), IPAddress.Parse("11.0.0.0").ConvertToUint()), },
            new RuleIpRange[] { new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.0.0").ConvertToUint()) },
            new RuleIpRange[] { new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.0.0").ConvertToUint()) },
            OverlapType.Partial
        };
        yield return new object[]
        {
            new RuleIpRange[] 
            {
                new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.0.0").ConvertToUint()),
                new(IPAddress.Parse("25.0.0.0").ConvertToUint(), IPAddress.Parse("25.0.0.0").ConvertToUint()), 
            },
            new RuleIpRange[]
            { 
                new(IPAddress.Parse("9.0.0.0").ConvertToUint(), IPAddress.Parse("11.0.0.0").ConvertToUint()), 
                new(IPAddress.Parse("20.0.0.0").ConvertToUint(), IPAddress.Parse("30.0.0.0").ConvertToUint()) 
            },
            new RuleIpRange[]
            {
                new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.0.0").ConvertToUint()),
                new(IPAddress.Parse("25.0.0.0").ConvertToUint(), IPAddress.Parse("25.0.0.0").ConvertToUint()) 
            },
            OverlapType.Full
        };
        yield return new object[]
        {
            new RuleIpRange[] 
            {
                new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.255.255").ConvertToUint()),
            },
            new RuleIpRange[]
            { 
                new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.127.255").ConvertToUint()), 
                new(IPAddress.Parse("10.0.128.0").ConvertToUint(), IPAddress.Parse("10.0.255.255").ConvertToUint()) 
            },
            new RuleIpRange[]
            {
                new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.255.255").ConvertToUint()),
            },
            OverlapType.Full
        };
        yield return new object[]
        {
            new RuleIpRange[] 
            {
                new(IPAddress.Parse("9.0.0.0").ConvertToUint(), IPAddress.Parse("11.0.255.255").ConvertToUint()),
            },
            new RuleIpRange[]
            { 
                new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.127.255").ConvertToUint()), 
                new(IPAddress.Parse("10.0.128.0").ConvertToUint(), IPAddress.Parse("10.0.255.255").ConvertToUint()) 
            },
            new RuleIpRange[]
            {
                new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.255.255").ConvertToUint()),
            },
            OverlapType.Partial
        };
        yield return new object[]
        {
            new RuleIpRange[] { new(IPAddress.Parse("9.0.0.0").ConvertToUint(), IPAddress.Parse("11.0.0.0").ConvertToUint()) },
            new RuleIpRange[] { new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.0.0").ConvertToUint()) },
            new RuleIpRange[] { new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.0.0").ConvertToUint()) },
            OverlapType.Partial
        };
    }

    [Theory]
    [MemberData(nameof(IpOverlaps))]
    public void TestSourceIpsOverlaps_Match(RuleIpRange[] sourceIps, RuleIpRange[] comparisonIps, RuleIpRange[] expectedMatch, OverlapType expectedOverlapType)
    {
        var sourceRule = BaseRule with { SourceIps = sourceIps };
        var comparisonRule = BaseRule with { SourceIps = comparisonIps };
        var results = OverlapAnalyzer.CheckForOverlap(sourceRule, [comparisonRule]);

        var baseOverlapSummary = new OverlapSummary(BaseRule, OverlapType.Partial, []);
        var baseOverlap = new Overlap(OverlapType.Full, BaseRule, [new()], [new()], [new()], NetworkProtocols.Any);
        Overlap[] expected = [baseOverlap with { OverlapType = expectedOverlapType, OverlappingRule = comparisonRule, OverlappingSourceRanges = expectedMatch }];

        Assert.True(expected.ElementByElementCompare(results.Overlaps, OverlapEquals));
    }

    [Theory]
    [MemberData(nameof(IpOverlaps))]
    public void TestDestinationIpsOverlaps_Match(RuleIpRange[] destinationIps, RuleIpRange[] comparisonIps, RuleIpRange[] expectedMatch, OverlapType expectedOverlapType)
    {
        var sourceRule = BaseRule with { DestinationIps = destinationIps };
        var comparisonRule = BaseRule with { DestinationIps = comparisonIps };
        var results = OverlapAnalyzer.CheckForOverlap(sourceRule, [comparisonRule]);

        var baseOverlapSummary = new OverlapSummary(BaseRule, OverlapType.Partial, []);
        var baseOverlap = new Overlap(OverlapType.Full, BaseRule, [new()], [new()], [new()], NetworkProtocols.Any);
        Overlap[] expected = [baseOverlap with { OverlapType = expectedOverlapType, OverlappingRule = comparisonRule, OverlappingDestinationRanges = expectedMatch }];

        Assert.True(expected.ElementByElementCompare(results.Overlaps, OverlapEquals));
    }

    public static IEnumerable<object[]> IpsNoOverlap()
    {
        yield return new object[]
        {
            new RuleIpRange[] { new(IPAddress.Parse("10.0.1.0").ConvertToUint(), IPAddress.Parse("10.0.2.0").ConvertToUint()) },
            new RuleIpRange[] { new(IPAddress.Parse("9.0.0.0").ConvertToUint(), IPAddress.Parse("9.1.0.0").ConvertToUint()) }
        };
        yield return new object[]
        {
            new RuleIpRange[] { new(IPAddress.Parse("9.0.0.0").ConvertToUint(), IPAddress.Parse("11.0.0.0").ConvertToUint()), },
            new RuleIpRange[] { new(IPAddress.Parse("13.0.0.0").ConvertToUint(), IPAddress.Parse("13.0.0.0").ConvertToUint()) },
        };
        yield return new object[]
        {
            new RuleIpRange[] 
            {
                new(IPAddress.Parse("10.0.0.0").ConvertToUint(), IPAddress.Parse("10.0.0.255").ConvertToUint()),
                new(IPAddress.Parse("10.0.2.0").ConvertToUint(), IPAddress.Parse("10.0.2.255").ConvertToUint()), 
            },
            new RuleIpRange[]
            { 
                new(IPAddress.Parse("9.0.0.0").ConvertToUint(), IPAddress.Parse("9.255.255.255").ConvertToUint()), 
                new(IPAddress.Parse("10.0.1.0").ConvertToUint(), IPAddress.Parse("10.0.1.255").ConvertToUint()),
                new(IPAddress.Parse("10.0.3.0").ConvertToUint(), IPAddress.Parse("10.0.3.0").ConvertToUint()) 
            }
        };
    }

    [Theory]
    [MemberData(nameof(IpsNoOverlap))]
    public void TestSourceIpsOverlaps_NoMatch(RuleIpRange[] sourceIps, RuleIpRange[] comparisonIps)
    {
        var sourceRule = BaseRule with { SourceIps = sourceIps };
        var comparisonRule = BaseRule with { SourceIps = comparisonIps };
        var results = OverlapAnalyzer.CheckForOverlap(sourceRule, [comparisonRule]);

        Assert.Empty(results.Overlaps);
        Assert.Equal(OverlapType.None, results.CumulativeOverlap);
    }

    [Theory]
    [MemberData(nameof(IpsNoOverlap))]
    public void TestDestinationIpsOverlaps_NoMatch(RuleIpRange[] destinationIps, RuleIpRange[] comparisonIps)
    {
        var sourceRule = BaseRule with { DestinationIps = destinationIps };
        var comparisonRule = BaseRule with { DestinationIps = comparisonIps };
        var results = OverlapAnalyzer.CheckForOverlap(sourceRule, [comparisonRule]);

        Assert.Empty(results.Overlaps);
        Assert.Equal(OverlapType.None, results.CumulativeOverlap);
    }

    public static IEnumerable<object[]> CumulativeOverlaps()
    {
        yield return new object[]
        {
            NetworkProtocols.Any,
            new Overlap[] 
            {
                BaseOverlap with { OverlappingProtocols = NetworkProtocols.ICMP }
            },
            OverlapType.Partial
        };
        yield return new object[]
        {
            NetworkProtocols.Any,
            Array.Empty<Overlap>(),
            OverlapType.None
        };
        yield return new object[]
        {
            NetworkProtocols.ICMP,
            new Overlap[] 
            {
                BaseOverlap with { OverlappingProtocols = NetworkProtocols.Any }
            },
            OverlapType.Full
        };
        yield return new object[]
        {
            NetworkProtocols.TCP | NetworkProtocols.UDP,
            new Overlap[] 
            {
                BaseOverlap with { OverlappingProtocols = NetworkProtocols.UDP | NetworkProtocols.ICMP }
            },
            OverlapType.Partial
        };
    }

    [Theory]
    [MemberData(nameof(CumulativeOverlaps))]
    public void TestCumulativeOverlap(NetworkProtocols sourceProtocols, Overlap[] accumulatingOverlaps, OverlapType expected)
    {
        var sourceRule = BaseRule with { NetworkProtocols = sourceProtocols };
        var results = OverlapAnalyzer.GetCumulativeOverlap(sourceRule, accumulatingOverlaps);

        Assert.Equal(expected, results);
    }

    private static void AssertOverlapsMatch(OverlapSummary expected, OverlapSummary actual)
    {
        Assert.Equal(expected.CumulativeOverlap, actual.CumulativeOverlap);
        Assert.Equal(expected.SourceRule, expected.SourceRule);
        Assert.Equal(expected.Overlaps.Length, actual.Overlaps.Length);
        Assert.True(expected.Overlaps.ElementByElementCompare(actual.Overlaps, OverlapEquals));
    }

    private static bool OverlapEquals(Overlap? x, Overlap? y)
    {
        return (x?.OverlapType == y?.OverlapType)
            && (x?.OverlappingRule.Equals(y?.OverlappingRule) ?? false)
            && (x?.OverlappingSourceRanges.OrderBy(item => item.Start).ElementByElementCompare(y.OverlappingSourceRanges.OrderBy(item => item.Start)) ?? false)
            && (x?.OverlappingDestinationRanges.OrderBy(item => item.Start).ElementByElementCompare(y.OverlappingDestinationRanges.OrderBy(item => item.Start)) ?? false)
            && (x?.OverlappingPorts.OrderBy(item => item.Start).ElementByElementCompare(y.OverlappingPorts.OrderBy(item => item.Start)) ?? false)
            && (x?.OverlappingProtocols.Equals(y?.OverlappingProtocols) ?? false);
    }
}