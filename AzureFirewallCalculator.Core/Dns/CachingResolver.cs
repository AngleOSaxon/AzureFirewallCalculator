
namespace AzureFirewallCalculator.Core.Dns;

public class CachingResolver(StaticDnsResolver manualDns, DynamicResolver fallbackResolver) : IDnsResolver
{
    public StaticDnsResolver ManualDns { get; } = manualDns;
    public DynamicResolver FallbackResolver { get; } = fallbackResolver;
    public StaticDnsResolver CachingDns { get; } = new StaticDnsResolver();
    private HashSet<string> failedLookups = new(StringComparer.CurrentCultureIgnoreCase);

    public async Task<uint[]> ResolveAddress(string fqdn)
    {
        var result = await ManualDns.ResolveAddress(fqdn);
        if (result.Length > 0)
        {
            return result;
        }

        result = await CachingDns.ResolveAddress(fqdn);
        if (result.Length > 0 || failedLookups.Contains(fqdn))
        {
            return result;
        }

        result = await FallbackResolver.ResolveAddress(fqdn);
        if (result.Length == 0)
        {
            failedLookups.Add(fqdn);
        }
        else
        {
            CachingDns.FqdnLookup.Add(fqdn, result);
        }

        return result;
    }
}