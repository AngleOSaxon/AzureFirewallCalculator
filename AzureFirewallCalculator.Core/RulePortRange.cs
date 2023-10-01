using Microsoft.Extensions.Logging;

namespace AzureFirewallCalculator.Core;

public readonly record struct RulePortRange
{
    public readonly ushort Start;

    public readonly ushort End;

    public RulePortRange(ushort start, ushort end)
    {
        Start = start;
        End = end;
    }

    public static RulePortRange? Parse(string source, ILogger logger)
    {
        if (source == "*")
        {
            return new RulePortRange(ushort.MinValue, ushort.MaxValue);
        }

        var split = source.Split('-');
        if (split.Length == 2 && ushort.TryParse(split[0], out var start) && ushort.TryParse(split[1], out var end))
        {
            return new RulePortRange(start, end);
        }

        if (ushort.TryParse(source, out var port))
        {
            return new RulePortRange(port, port);
        }

        logger.LogWarning("Unable to parse port '{unparsablePort}'", source);
        return null;
    }
}