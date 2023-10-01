
using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;

namespace AzureFirewallCalculator.Core.Dns;

public class GoogleDnsResolver : IDnsResolver
{
    public GoogleDnsResolver(HttpClient httpClient, ILogger<GoogleDnsResolver> logger)
    {
        HttpClient = httpClient;
        Logger = logger;
    }

    public HttpClient HttpClient { get; }
    public ILogger<GoogleDnsResolver> Logger { get; }

    public async Task<uint[]> ResolveAddress(string fqdn)
    {
        var builder = new UriBuilder("https://dns.google/resolve")
        {
            Query = $"name={fqdn}"
        };
        var result = await HttpClient.GetFromJsonAsync<GoogleDnsResponse>(builder.Uri);
        
        if ((result?.Answer?.Length ?? 0) == 0)
        {
            Logger.LogWarning("No results from Google DNS for {fqdn}", fqdn);
            return Array.Empty<uint>();
        }

        // Null-checking should be covered by previous if-statement
        return result!.Answer!
            .Where(item => item.Type == DnsRequestType.A)
            .Select(item => IPAddress.Parse(item.Data).ConvertToUint())
            .ToArray();;
    }
}