using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace AzureFirewallCalculator.Core;

public class NetworkRuleComparer : IEqualityComparer<NetworkRule>
{
    private readonly IpRangeComparer rangeComparer = new();

    public bool Equals(NetworkRule? x, NetworkRule? y)
    {
        if (x == null || y == null)
        {
            return x == y;
        }

        return x.Name == y.Name 
            && x.SourceIps.SequenceEqual(y.SourceIps, rangeComparer) 
            && x.AllDestinationIps.SequenceEqual(y.AllDestinationIps, rangeComparer) 
            && x.DestinationPorts.SequenceEqual(y.DestinationPorts)
            && x.NetworkProtocols == y.NetworkProtocols;
    }

    public int GetHashCode([DisallowNull] NetworkRule obj)
    {
        return obj.Name.GetHashCode() 
            ^ obj.SourceIps.Aggregate(seed: 0, func: (x, next) => x ^ next.Start.GetHashCode() ^ next.End.GetHashCode())
            ^ obj.DestinationIps.Aggregate(seed: 0, func: (x, next) => x ^ next.Start.GetHashCode() ^ next.End.GetHashCode())
            ^ obj.DestinationPorts.Aggregate(seed: 0, func: (x, next) => x ^ next.Start.GetHashCode() ^ next.End.GetHashCode())
            ^ obj.NetworkProtocols.GetHashCode();
    }
}

public class ApplicationRuleComparer : IEqualityComparer<ApplicationRule>
{
    private readonly IpRangeComparer rangeComparer = new();

    public bool Equals(ApplicationRule? x, ApplicationRule? y)
    {
        if (x == null || y == null)
        {
            return false;
        }

        return x.Name == y.Name && x.SourceIps.SequenceEqual(y.SourceIps, rangeComparer) && x.DestinationFqdns.SequenceEqual(y.DestinationFqdns) && x.Protocols.SequenceEqual(y.Protocols);
    }

    public int GetHashCode([DisallowNull] ApplicationRule obj)
    {
        return obj.Name.GetHashCode() 
            ^ obj.SourceIps.Aggregate(seed: 0, func: (x, next) => x ^ next.Start.GetHashCode() ^ next.End.GetHashCode())
            ^ obj.DestinationFqdns.Aggregate(seed: 0, func: (x, next) => x ^ next.GetHashCode())
            ^ obj.Protocols.Aggregate(seed: 0, func: (x, next) => x ^ next.GetHashCode());
    }
}

public class IpRangeComparer : IEqualityComparer<RuleIpRange>
{
    public bool Equals(RuleIpRange x, RuleIpRange y)
    {
        return x.Start == y.Start && x.End == y.End;
    }

    public int GetHashCode([DisallowNull] RuleIpRange obj)
    {
        return obj.Start.GetHashCode() ^ obj.End.GetHashCode();
    }
}