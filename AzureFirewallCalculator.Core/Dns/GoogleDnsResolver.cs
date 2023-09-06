
using System.Net;
using System.Net.Http.Json;

namespace AzureFirewallCalculator.Core.Dns;

public class GoogleDnsResolver : IDnsResolver
{
    public GoogleDnsResolver(HttpClient httpClient)
    {
        HttpClient = httpClient;
    }

    public HttpClient HttpClient { get; }

    public async Task<uint[]> ResolveAddress(string fqdn)
    {
        var builder = new UriBuilder("https://dns.google/resolve")
        {
            Query = $"name={fqdn}"
        };
        var result = await HttpClient.GetFromJsonAsync<GoogleDnsResponse>(builder.Uri);
        
        if ((result?.Answer?.Length ?? 0) == 0)
        {
            Console.WriteLine($"No results from Google DNS for {fqdn}");
            return Array.Empty<uint>();
        }

        // Null-checking should be covered by previous if-statement
        return result!.Answer!
            .Where(item => item.Type == DnsRequestType.A)
            .Select(item => IPAddress.Parse(item.Data).ConvertToUint())
            .ToArray();;
    }
}