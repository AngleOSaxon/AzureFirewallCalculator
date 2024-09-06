using System.Net;
using System.Net.Sockets;
using AzureFirewallCalculator.Core.Tags;
using Microsoft.Extensions.Logging;

namespace AzureFirewallCalculator.Core;

public readonly record struct RuleIpRange
{
    public uint Start { get; }

    public uint End { get; }

    public IpSource[] SourcedFrom { get; }

    public RuleIpRange()
    {
        SourcedFrom = [];
    }

    public RuleIpRange(uint start, uint end, IpSource[]? sourcedFrom = null)
    {
        if (end < start)
        {
            throw new ArgumentException($"Invalid range.  End value ({end}) cannot come before Start value ({start})");
        }
        Start = start;
        End = end;
        SourcedFrom = sourcedFrom ?? [];
    }

    public bool Contains(RuleIpRange range)
    {
        return Start <= range.Start && End >= range.End;
    }

    public override string ToString()
    {
        var start = new IPAddress(BitConverter.GetBytes(Start).Reverse().ToArray());

        if (Start == End)
        {
            return start.ToString();
        }

        var end = new IPAddress(BitConverter.GetBytes(End).Reverse().ToArray());

        return $"{start} - {end}";
    }

    public static RuleIpRange[] Parse(string source, ServiceTag[] serviceTags, IpSourceType sourceType, string sourceName, ILogger logger)
    {
        var result = Parse(source, sourceType, sourceName, logger);
        if (result != null)
        {
            return [result.Value];
        }

        var serviceTag = serviceTags.FirstOrDefault(item => item.Name.Equals(source, StringComparison.CurrentCultureIgnoreCase));
        if (serviceTag == null)
        {
            return [];
        }

        return serviceTag.AddressPrefixes.Select((item) => Parse(item, IpSourceType.ServiceTag, serviceTag.Name, logger))
            .Where(item => item != null)
            .Cast<RuleIpRange>()
            .ToArray();
    }

    public static RuleIpRange? Parse(string source, IpSourceType sourceType, string sourceName, ILogger logger)
    {
        if (source == "*")
        {
            return new RuleIpRange(0, uint.MaxValue, [new (sourceType, sourceName)]);
        }

        if (source.Contains('-'))
        {
            var split = source.Split('-');

            if (!IPAddress.TryParse(split[0].Trim(), out var startIp) || !IPAddress.TryParse(split[1].Trim(), out var endIp))
            {
                throw new ArgumentException($"Failed to parse range '{source}'");
            }

            if (startIp.AddressFamily == AddressFamily.InterNetworkV6 || endIp.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // logger.LogInformation("Skipping IPv6 Address '{skippedAddress}'", source);
                return null;
            }

            var start = startIp.ConvertToUint();
            var end = endIp.ConvertToUint();

            return new RuleIpRange(start, end, [new (sourceType, sourceName)]);
        }

        if (source.Contains('/'))
        {
            var split = source.Split('/');

            if (!IPAddress.TryParse(split[0], out var ip) || !ushort.TryParse(split[1], out var maskSize))
            {
                throw new ArgumentException($"Failed to parse CIDR '{source}'");
            }

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // logger.LogInformation("Skipping IPv6 Address '{skippedAddress}'", source);
                return null;
            }

            var startIp = ip.ConvertToUint();

            // Can't shift by more than n
            if (maskSize == 32)
            {
                return new RuleIpRange(startIp, startIp, [new (sourceType, sourceName)]);
            }

            var bitMask = uint.MaxValue >> maskSize;
            var maxIp = startIp | bitMask;
            return new RuleIpRange(startIp, maxIp, [new (sourceType, sourceName)]);
        }
        else if(IPAddress.TryParse(source, out var ip))
        {
            var ipBytes = ip.ConvertToUint();
            return new RuleIpRange(ipBytes, ipBytes, [new (sourceType, sourceName)]);
        }
        
        logger.LogInformation("Unparsable IP range: '{unparsableIpRange}'", source);

        return null;
    }
}