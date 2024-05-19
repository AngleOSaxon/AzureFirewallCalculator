using System.Diagnostics.CodeAnalysis;
using System.Net;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Tests;

public class TestOverlapAnalysis
{

    public static IEnumerable<object[]> SourceData() 
    {
        var sourceRule = new NetworkRule(
            name: "Test",
            sourceIps: [ new RuleIpRange(IPAddress.Parse("10.0.1.0").ConvertToUint(), IPAddress.Parse("10.0.1.127").ConvertToUint()) ],
            destinationIps: [ new RuleIpRange(IPAddress.Parse("10.0.2.128").ConvertToUint(), IPAddress.Parse("10.0.2.255").ConvertToUint()) ],
            destinationPorts: [ new RulePortRange(88, 88) ],
            destinationFqdns: [],
            networkProtocols: NetworkProtocols.TCP,
            dnsResolver: null!
        );
        var comparisonRules = new NetworkRule[]
        {
            new(
                name: "ShouldMatch",
                sourceIps: [ new RuleIpRange(IPAddress.Parse("10.0.1.0").ConvertToUint(), IPAddress.Parse("10.0.1.255").ConvertToUint()) ],
                destinationIps: [ new RuleIpRange(IPAddress.Parse("10.0.2.0").ConvertToUint(), IPAddress.Parse("10.0.3.0").ConvertToUint()) ],
                destinationPorts: [ new RulePortRange(50, 100) ],
                destinationFqdns: [],
                networkProtocols: NetworkProtocols.TCP,
                dnsResolver: null!
            ),
            new(
                name: "ShouldNotMatch",
                sourceIps: [ new RuleIpRange(IPAddress.Parse("10.1.1.0").ConvertToUint(), IPAddress.Parse("10.1.1.255").ConvertToUint()) ],
                destinationIps: [ new RuleIpRange(IPAddress.Parse("10.1.2.0").ConvertToUint(), IPAddress.Parse("10.1.3.0").ConvertToUint()) ],
                destinationPorts: [ new RulePortRange(50, 100) ],
                destinationFqdns: [],
                networkProtocols: NetworkProtocols.TCP,
                dnsResolver: null!
            ),
        };
        yield return new object[] 
        { 
            sourceRule,
            comparisonRules,
            new OverlapAnalyzer.OverlapSummary(
                SourceRule: sourceRule,
                CumulativeOverlap: OverlapAnalyzer.OverlapType.Partial,
                Overlaps:
                [
                    new(
                        OverlapType: OverlapAnalyzer.OverlapType.Full,
                        OverlappingRule: comparisonRules[0],
                        OverlappingSourceRanges: [new(start: IPAddress.Parse("10.0.1.0").ConvertToUint(), end: IPAddress.Parse("10.0.1.127").ConvertToUint())],
                        OverlappingDestinationRanges: [new(start: IPAddress.Parse("10.0.2.128").ConvertToUint(), end: IPAddress.Parse("10.0.2.255").ConvertToUint())],
                        OverlappingPorts: [new RulePortRange(88, 88)],
                        OverlappingProtocols: NetworkProtocols.TCP
                    )
                ]
            )
         };
    }

    [Theory]
    [MemberData(nameof(SourceData))]
    public void TestNetworkRuleOverlapAnalysis(NetworkRule rule, NetworkRule[] comparisonRules, OverlapAnalyzer.OverlapSummary expectedOverlap)
    {
        var result = OverlapAnalyzer.CheckForOverlap(sourceRule: rule, comparisonRules: comparisonRules);
        AssertOverlapsMatch(expectedOverlap, result);
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
            && (x?.OverlappingSourceRanges.ElementByElementCompare(y.OverlappingSourceRanges) ?? false)
            && (x?.OverlappingDestinationRanges.ElementByElementCompare(y.OverlappingDestinationRanges) ?? false)
            && (x?.OverlappingPorts.ElementByElementCompare(y.OverlappingPorts) ?? false)
            && (x?.OverlappingProtocols.Equals(y?.OverlappingProtocols) ?? false);
    }
}