namespace AzureFirewallCalculator.Core;


public enum RuleAction
{
    Allow,
    Deny,
    Pass
}

[Flags]
public enum NetworkProtocols
{
    None = 0,
    ICMP = 1,
    TCP = 2,
    UDP = 4,
    Any = ICMP | TCP | UDP
}

public enum ApplicationProtocol
{
    Http,
    Https,
    Mssql,
}

public enum OverlapType
{
    None,
    Partial,
    Full
}

public enum IpSourceType
{
    IpAddress,
    IpGroup,
    ServiceTag,
    Fqdn
}