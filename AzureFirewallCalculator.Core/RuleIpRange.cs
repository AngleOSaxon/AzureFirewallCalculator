using System.Net;

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
        var end = new IPAddress(BitConverter.GetBytes(End).Reverse().ToArray());

        return $"{start} - {end}";
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

            var startIp = ip.ConvertToUint();
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
        Console.Error.WriteLine($"Unparsable IP range: '{source}'");

        return null;
    }
}