using System.Net;

namespace AzureFirewallCalculator.Core;

public static class Utils
{
    public static uint ConvertToUint(this IPAddress ipAddress) => BitConverter.ToUInt32(ipAddress.GetAddressBytes().Reverse().ToArray());

    public static IPAddress ConvertToIpAddress(this uint numericIp) => new(BitConverter.GetBytes(numericIp).Reverse().ToArray());

    public static NetworkProtocols ParseNetworkProtocols(this string[] protocolNames) => protocolNames.Aggregate(NetworkProtocols.None, (seed, item) => seed | Enum.Parse<NetworkProtocols>(item));

    // Taken from https://stackoverflow.com/a/35874937
    public static async Task<IEnumerable<TResult>> SelectManyAsync<TSource, TResult>(this IEnumerable<TSource> source, Func<TSource, Task<IEnumerable<TResult>>> resultSelector) 
        => (await Task.WhenAll(source.Select(resultSelector))).SelectMany(s => s);
}