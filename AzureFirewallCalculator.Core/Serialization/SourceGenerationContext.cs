using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Core.PowershellSource;
using AzureFirewallCalculator.Core.Tags;

namespace AzureFirewallCalculator.Core.Serialization;

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(ServiceTags))]
[JsonSerializable(typeof(ServiceTag[]))]
[JsonSerializable(typeof(ServiceTag))]
[JsonSerializable(typeof(GoogleDnsResponse))]
[JsonSerializable(typeof(IpGroup[]))]
[JsonSerializable(typeof(PowershellSource.Firewall))]
public partial class SourceGenerationContext : JsonSerializerContext
{
}