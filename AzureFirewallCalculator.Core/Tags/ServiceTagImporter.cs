using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using AzureFirewallCalculator.Core.Serialization;

namespace AzureFirewallCalculator.Core.Tags;

public class ServiceTagImporter
{
    private static readonly HttpClient HttpClient = new();

    public static async Task<ServiceTag[]> GetServiceTags(DateTimeOffset dateTime)
    {
        DayOfWeek currentDay = dateTime.DayOfWeek;
        var offset = (int)currentDay - (int)DayOfWeek.Monday;
        if (offset < 0)
        {
            offset += 7;
        }
        var postedDate = dateTime.AddDays(-offset);
        if (postedDate.DayOfWeek != DayOfWeek.Monday)
        {
            throw new Exception($"Incorrect date calculation; found {postedDate.DayOfWeek} instead of {DayOfWeek.Monday}");
        }
        var baseTagUrl = "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_{0:yyyyMMdd}.json";
        var tagUrl = string.Format(baseTagUrl, postedDate);

        var tagResult = await HttpClient.GetAsync(tagUrl);
        // Walk backward in time if we can't find a recent set of service tags
        while (tagResult.StatusCode == HttpStatusCode.NotFound && postedDate > dateTime.AddDays(-180))
        {
            postedDate = postedDate.AddDays(-7);
            tagUrl = string.Format(baseTagUrl, postedDate);
            tagResult = await HttpClient.GetAsync(tagUrl);
        }

        var tags = await tagResult.Content.ReadFromJsonAsync(SourceGenerationContext.Default.ServiceTags);
        
        if (tags == null)
        {
            return [];
        }
        return tags.Values.Select(item => new ServiceTag(Name: item.Name, AddressPrefixes: [.. item.Properties.AddressPrefixes])).ToArray();
    }
}