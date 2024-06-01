using System.Net;

namespace AzureFirewallCalculator.Core;

public readonly struct IpAddressBytes(string ipAddress)
{
    private readonly uint Bytes = IPAddress.Parse(ipAddress).ConvertToUint();

    public static implicit operator uint(IpAddressBytes ipAddressBytes) => ipAddressBytes.Bytes;
}