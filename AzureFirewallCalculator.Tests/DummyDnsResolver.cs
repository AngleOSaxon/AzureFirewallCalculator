using AzureFirewallCalculator.Core.Dns;

namespace AzureFirewallCalculator.Tests;

public class DummyDnsResolver : IDnsResolver
{
    public static readonly IDnsResolver DummyResolver = new DummyDnsResolver();

    public Task<uint[]> ResolveAddress(string fqdn) => Task.FromResult<uint[]>([0]);
}