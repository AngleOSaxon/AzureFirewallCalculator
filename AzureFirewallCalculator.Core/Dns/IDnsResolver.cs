namespace AzureFirewallCalculator.Core.Dns;

public interface IDnsResolver
{
    Task<uint[]> ResolveAddress(string fqdn);
}