using SystemDns = System.Net.Dns;

namespace AzureFirewallCalculator.Core.Dns;

public class DynamicResolver : IDnsResolver
{
    // TODO: investigate allowing custom DNS servers
    // may require implementing simple DNS client: https://stackoverflow.com/a/47277960
    // see also Julia Evans?
    // TODO: DNS lookup without exceptions for unknown names.  Likely also requires custom client
    public async Task<uint[]> ResolveAddress(string fqdn)
    {
        var entries = await SystemDns.GetHostEntryAsync(fqdn);
        return entries.AddressList
            .Where(item => item.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
            .Select(item => item.ConvertToUint())
            .ToArray();
    }
}