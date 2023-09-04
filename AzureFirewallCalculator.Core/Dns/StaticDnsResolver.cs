using System.Net;

namespace AzureFirewallCalculator.Core.Dns;

public class StaticDnsResolver : IDnsResolver
{
    public Dictionary<string, uint[]> FqdnLookup { get; }

    public StaticDnsResolver(Dictionary<string, uint[]> fqdnLookup)
    {
        FqdnLookup = fqdnLookup;
    }

    public StaticDnsResolver(Dictionary<string, IPAddress[]> fqdnLookup)
    {
        FqdnLookup = fqdnLookup.ToDictionary(item => item.Key, item => item.Value.Select(item => item.ConvertToUint()).ToArray());
    }

    public Task<uint[]> ResolveAddress(string fqdn) => FqdnLookup.ContainsKey(fqdn) ? Task.FromResult(FqdnLookup[fqdn]) : Task.FromResult(Array.Empty<uint>());
}