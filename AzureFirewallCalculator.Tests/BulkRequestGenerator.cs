using System.Collections.Immutable;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Tests;

public static class BulkRequestGenerator
{
    // Number of bits set in the enum; index is the value of the enum
    private static readonly int[] NetworkProtocolCount = [
        0, 1, 1, 2, 1, 2, 2, 3
    ];

    public static ImmutableList<NetworkRequest> GenerateRequests(NetworkRule rule)
    {
        var requests = new List<NetworkRequest>(rule.SourceIps.Length * rule.DestinationIps.Length * rule.DestinationPorts.Length * NetworkProtocolCount[(int)rule.NetworkProtocols]);
        foreach (var sourceIp in rule.SourceIps.SelectMany(GetAllIpsInRange))
        {
            foreach (var destinationIp in rule.DestinationIps.SelectMany(GetAllIpsInRange))
            {
                if (rule.NetworkProtocols.HasFlag(NetworkProtocols.ICMP))
                {
                    requests.Add(new (
                        sourceIp: sourceIp,
                        destinationIp: destinationIp,
                        destinationPort: null,
                        protocol: NetworkProtocols.ICMP
                    ));
                }
                
                foreach (var port in rule.DestinationPorts.SelectMany(GetAllPortsInRange))
                {
                    if (rule.NetworkProtocols.HasFlag(NetworkProtocols.TCP))
                    {
                        requests.Add(new (
                            sourceIp: sourceIp,
                            destinationIp: destinationIp,
                            destinationPort: port,
                            protocol: NetworkProtocols.TCP
                        ));
                    }
                    if (rule.NetworkProtocols.HasFlag(NetworkProtocols.UDP))
                    {
                        requests.Add(new (
                            sourceIp: sourceIp,
                            destinationIp: destinationIp,
                            destinationPort: port,
                            protocol: NetworkProtocols.UDP
                        ));
                    }
                }
            }
        }
        return [.. requests];
    }

    private static IEnumerable<uint> GetAllIpsInRange(RuleIpRange range)
    {
        yield return range.Start;
        for (uint i = 1; i <= range.End - range.Start; i++)
        {
            yield return range.Start + i;
        }
    }

    private static IEnumerable<ushort> GetAllPortsInRange(RulePortRange range)
    {
        for (ushort i = 0; i <= range.End - range.Start; i++)
        {
            yield return (ushort)(range.Start + i);
        }
    }
}