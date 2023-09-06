using System.Net;
using System.Net.Sockets;
using AzureFirewallCalculator.Core.Tags;

namespace AzureFirewallCalculator.Core;

public readonly record struct RuleIpRange
{
    public uint Start { get; }

    public uint End { get; }

    public RuleIpRange(uint start, uint end)
    {
        Start = start;
        End = end;
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

    public static RuleIpRange[] Parse(string source, ServiceTags serviceTags)
    {
        var result = Parse(source);
        if (result != null)
        {
            return new RuleIpRange[] { result.Value };
        }

        var serviceTag = serviceTags.Values.FirstOrDefault(item => item.Name.Equals(source, StringComparison.CurrentCultureIgnoreCase));
        if (serviceTag == null)
        {
            return Array.Empty<RuleIpRange>();
        }

        return serviceTag.Properties.AddressPrefixes.Select(Parse)
            .Where(item => item != null)
            .Cast<RuleIpRange>()
            .ToArray();
    }

    public static RuleIpRange? Parse(string source)
    {
        if (source == "*")
        {
            return new RuleIpRange(0, uint.MaxValue);
        }

        if (source.Contains('-'))
        {
            var split = source.Split('-');

            if (!IPAddress.TryParse(split[0], out var startIp) || !IPAddress.TryParse(split[1], out var endIp))
            {
                throw new ArgumentException($"Failed to parse range '{source}'");
            }

            if (startIp.AddressFamily == AddressFamily.InterNetworkV6 || endIp.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Console.WriteLine($"Skipping IPv6 Address '{source}'");
                return null;
            }

            var start = startIp.ConvertToUint();
            var end = endIp.ConvertToUint();

            return new RuleIpRange(start, end);
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
                Console.WriteLine($"Skipping IPv6 Address '{source}'");
                return null;
            }

            var startIp = ip.ConvertToUint();

            // Can't shift by more than n
            if (maskSize == 32)
            {
                return new RuleIpRange(startIp, startIp);
            }

            var bitMask = uint.MaxValue >> maskSize;
            var maxIp = startIp | bitMask;
            return new RuleIpRange(startIp, maxIp);
        }
        else if(IPAddress.TryParse(source, out var ip))
        {
            var ipBytes = ip.ConvertToUint();
            return new RuleIpRange(ipBytes, ipBytes);
        }
        
        // TODO: Incorporate MS IP Ranges?
        // TODO: Logging plans
        Console.WriteLine($"Unparsable IP range: '{source}'");

        return null;
    }
}