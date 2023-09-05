namespace AzureFirewallCalculator.Core.Tags;

public record class ServiceTagProperties(int ChangeNumber, string Region, int RegionId, string Platyform, string SystemService, string[] AddressPrefixes, string[] NetworkFeatures);

public record class ServiceTagValue(string Name, string Id, ServiceTagProperties Properties);

public record class ServiceTags(int ChangeNumber, string Cloud, ServiceTagValue[] Values);