using System.Collections;
using System.Net;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Tests.TheoryData;

public class OverlapAnalysisData : IEnumerable<object[]>
{
    public IEnumerator<object[]> GetEnumerator() 
    {
        var sourceRule = new NetworkRule(
            name: "Test",
            sourceIps: [ new RuleIpRange(IPAddress.Parse("10.0.1.0").ConvertToUint(), IPAddress.Parse("10.0.1.127").ConvertToUint()) ],
            destinationIps: [ new RuleIpRange(IPAddress.Parse("10.0.2.128").ConvertToUint(), IPAddress.Parse("10.0.2.255").ConvertToUint()) ],
            destinationPorts: [ new RulePortRange(88, 88) ],
            destinationFqdns: [],
            networkProtocols: NetworkProtocols.TCP,
            dnsResolver: DummyDnsResolver.DummyResolver
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
                dnsResolver: DummyDnsResolver.DummyResolver
            ),
            new(
                name: "ShouldNotMatch",
                sourceIps: [ new RuleIpRange(IPAddress.Parse("10.1.1.0").ConvertToUint(), IPAddress.Parse("10.1.1.255").ConvertToUint()) ],
                destinationIps: [ new RuleIpRange(IPAddress.Parse("10.1.2.0").ConvertToUint(), IPAddress.Parse("10.1.3.0").ConvertToUint()) ],
                destinationPorts: [ new RulePortRange(50, 100) ],
                destinationFqdns: [],
                networkProtocols: NetworkProtocols.TCP,
                DummyDnsResolver.DummyResolver
            ),
        };
        yield return new object[] 
        { 
            sourceRule,
            comparisonRules,
            new OverlapSummary(
                SourceRule: sourceRule,
                CumulativeOverlap: OverlapType.Full,
                Overlaps:
                [
                    new(
                        OverlapType: OverlapType.Full,
                        OverlappingRule: comparisonRules[0],
                        OverlappingSourceRanges: [new(start: IPAddress.Parse("10.0.1.0").ConvertToUint(), end: IPAddress.Parse("10.0.1.127").ConvertToUint())],
                        OverlappingDestinationRanges: [new(start: IPAddress.Parse("10.0.2.128").ConvertToUint(), end: IPAddress.Parse("10.0.2.255").ConvertToUint())],
                        OverlappingPorts: [new RulePortRange(88, 88)],
                        OverlappingProtocols: NetworkProtocols.TCP
                    )
                ]
            )
         };
        sourceRule = new NetworkRule(
            name: "Test",
            sourceIps: [ new RuleIpRange(IPAddress.Parse("10.0.1.0").ConvertToUint(), IPAddress.Parse("10.0.1.127").ConvertToUint()) ],
            destinationIps: [ new RuleIpRange(IPAddress.Parse("10.0.2.128").ConvertToUint(), IPAddress.Parse("10.0.2.255").ConvertToUint()) ],
            destinationPorts: [ new RulePortRange(88, 88) ],
            destinationFqdns: [],
            networkProtocols: NetworkProtocols.UDP,
            dnsResolver: DummyDnsResolver.DummyResolver
        );
        comparisonRules =
        [
            new(
                name: "ShouldNotMatch",
                sourceIps: [ new RuleIpRange(IPAddress.Parse("10.0.1.0").ConvertToUint(), IPAddress.Parse("10.0.1.255").ConvertToUint()) ],
                destinationIps: [ new RuleIpRange(IPAddress.Parse("10.0.2.0").ConvertToUint(), IPAddress.Parse("10.0.3.0").ConvertToUint()) ],
                destinationPorts: [ new RulePortRange(50, 100) ],
                destinationFqdns: [],
                networkProtocols: NetworkProtocols.TCP,
                dnsResolver: DummyDnsResolver.DummyResolver
            ),
            new(
                name: "ShouldNotMatch",
                sourceIps: [ new RuleIpRange(IPAddress.Parse("10.1.1.0").ConvertToUint(), IPAddress.Parse("10.1.1.255").ConvertToUint()) ],
                destinationIps: [ new RuleIpRange(IPAddress.Parse("10.1.2.0").ConvertToUint(), IPAddress.Parse("10.1.3.0").ConvertToUint()) ],
                destinationPorts: [ new RulePortRange(50, 100) ],
                destinationFqdns: [],
                networkProtocols: NetworkProtocols.UDP,
                dnsResolver: DummyDnsResolver.DummyResolver
            ),
        ];
        yield return new object[] 
        { 
            sourceRule,
            comparisonRules,
            new OverlapSummary(
                SourceRule: sourceRule,
                CumulativeOverlap: OverlapType.None,
                Overlaps: []
            )
         };
         sourceRule = new NetworkRule(
            name: "Test",
            sourceIps: [ new RuleIpRange(IPAddress.Parse("10.0.1.0").ConvertToUint(), IPAddress.Parse("10.0.1.127").ConvertToUint()) ],
            destinationIps: [ new RuleIpRange(IPAddress.Parse("10.0.2.128").ConvertToUint(), IPAddress.Parse("10.0.2.255").ConvertToUint()) ],
            destinationPorts: [ new RulePortRange(88, 88) ],
            destinationFqdns: [],
            networkProtocols: NetworkProtocols.UDP,
            dnsResolver: DummyDnsResolver.DummyResolver
        );
        comparisonRules =
        [
            new(
                name: "ShouldMatch",
                sourceIps: [ new RuleIpRange(IPAddress.Parse("10.0.1.0").ConvertToUint(), IPAddress.Parse("10.0.1.255").ConvertToUint()) ],
                destinationIps: [ new RuleIpRange(IPAddress.Parse("10.0.2.0").ConvertToUint(), IPAddress.Parse("10.0.3.0").ConvertToUint()) ],
                destinationPorts: [ new RulePortRange(50, 100) ],
                destinationFqdns: [],
                networkProtocols: NetworkProtocols.TCP | NetworkProtocols.UDP,
                dnsResolver: DummyDnsResolver.DummyResolver
            ),
            new(
                name: "ShouldMatch",
                sourceIps: [ new RuleIpRange(IPAddress.Parse("10.0.1.0").ConvertToUint(), IPAddress.Parse("10.1.1.255").ConvertToUint()) ],
                destinationIps: [ new RuleIpRange(IPAddress.Parse("10.0.2.0").ConvertToUint(), IPAddress.Parse("10.1.3.0").ConvertToUint()) ],
                destinationPorts: [ new RulePortRange(50, 100) ],
                destinationFqdns: [],
                networkProtocols: NetworkProtocols.UDP,
                dnsResolver: DummyDnsResolver.DummyResolver
            ),
        ];
        yield return new object[] 
        { 
            sourceRule,
            comparisonRules,
            new OverlapSummary(
                SourceRule: sourceRule,
                CumulativeOverlap: OverlapType.Full,
                Overlaps: 
                [
                    new(
                        OverlapType: OverlapType.Full,
                        OverlappingRule: comparisonRules[0],
                        OverlappingSourceRanges: [new(start: IPAddress.Parse("10.0.1.0").ConvertToUint(), end: IPAddress.Parse("10.0.1.127").ConvertToUint())],
                        OverlappingDestinationRanges: [new(start: IPAddress.Parse("10.0.2.128").ConvertToUint(), end: IPAddress.Parse("10.0.2.255").ConvertToUint())],
                        OverlappingPorts: [new RulePortRange(88, 88)],
                        OverlappingProtocols: NetworkProtocols.UDP
                    ),
                    new(
                        OverlapType: OverlapType.Full,
                        OverlappingRule: comparisonRules[1],
                        OverlappingSourceRanges: [new(start: IPAddress.Parse("10.0.1.0").ConvertToUint(), end: IPAddress.Parse("10.0.1.127").ConvertToUint())],
                        OverlappingDestinationRanges: [new(start: IPAddress.Parse("10.0.2.128").ConvertToUint(), end: IPAddress.Parse("10.0.2.255").ConvertToUint())],
                        OverlappingPorts: [new RulePortRange(88, 88)],
                        OverlappingProtocols: NetworkProtocols.UDP
                    )
                ]
            )
         };
    }
    
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}