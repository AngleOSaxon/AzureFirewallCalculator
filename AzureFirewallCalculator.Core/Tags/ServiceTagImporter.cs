using System.Net.Http.Json;

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
        var postedDateString = postedDate.ToString("yyyyMMdd");
        var tagUrl = $"https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_{postedDateString}.json";

        var tags = await HttpClient.GetFromJsonAsync<ServiceTags>(tagUrl);
        if (tags == null)
        {
            return Array.Empty<ServiceTag>();
        }
        return tags.Values.Select(item => new ServiceTag(Name: item.Name, AddressPrefixes: item.Properties.AddressPrefixes.ToArray())).ToArray();
    }
}