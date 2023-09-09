using System.Net.Http.Json;

namespace AzureFirewallCalculator.Core.Tags;

public class ServiceTagImporter
{
    private static HttpClient HttpClient = new();

    public static async Task<ServiceTags> GetServiceTags()
    {
        // TODO: dynamically build
        const string tagUrl = "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230904.json";

        return (await HttpClient.GetFromJsonAsync<ServiceTags>(tagUrl))!;
    }
}