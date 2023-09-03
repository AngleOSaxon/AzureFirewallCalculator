using System.Net;

namespace AzureFirewallCalculator.Core;

public static class Utils
{
    public static uint ConvertToUint(this IPAddress ipAddress) => BitConverter.ToUInt32(ipAddress.GetAddressBytes().Reverse().ToArray());

    public static NetworkProtocols ParseNetworkProtocols(this string[] protocolNames) => protocolNames.Aggregate(NetworkProtocols.None, (seed, item) => seed | Enum.Parse<NetworkProtocols>(item));
}