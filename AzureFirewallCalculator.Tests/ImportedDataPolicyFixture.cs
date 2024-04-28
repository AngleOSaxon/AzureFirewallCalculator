using System.Net;
using System.Text.Json;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Core.Dns;
using Microsoft.Extensions.Logging.Abstractions;
using PowershellSource = AzureFirewallCalculator.Core.PowershellSource;

namespace AzureFirewallCalculator.Tests;

public class ImportedDataPolicyFixture : IDisposable
{
    public ImportedDataPolicyFixture()
    {
        var firewallExport = File.ReadAllText("./PowershellDataPolicy/firewall.json");
        var parsedFirewall = System.Text.Json.JsonSerializer.Deserialize<PowershellSource.Firewall>(firewallExport);

        var ipGroupExport = File.ReadAllText("./PowershellDataPolicy/ipGroups.json");
        var ipGroups = System.Text.Json.JsonSerializer.Deserialize<PowershellSource.IpGroup[]>(ipGroupExport)!.ToDictionary(item => item.Id, StringComparer.CurrentCultureIgnoreCase);

        var policyExport = File.ReadAllText("./PowershellDataPolicy/policy.json");
        var policies = System.Text.Json.JsonSerializer.Deserialize<PowershellSource.Policy[]>(policyExport)!.ToDictionary(item => item.Id, StringComparer.CurrentCultureIgnoreCase);

        var ruleCollectionGroupsExport = File.ReadAllText("./PowershellDataPolicy/ruleCollectionGroups.json");
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };
        options.Converters.Add(new PowershellSource.RuleCollectionJsonConverter());
        var ruleCollectionGroups = System.Text.Json.JsonSerializer.Deserialize<PowershellSource.RuleCollectionGroup[]>(ruleCollectionGroupsExport, options)!.ToDictionary(item => item.Properties.Id, StringComparer.CurrentCultureIgnoreCase);

        var dnsResolver = new CachingResolver(new StaticDnsResolver(new Dictionary<string, IPAddress[]>
        {
            ["sqlserver.antiwizard.net"] = [IPAddress.Parse("10.3.0.33")],
            ["mysql.antiwizard.net"] = [IPAddress.Parse("10.3.0.35")],
            ["cosmosdb.antiwizard.net"] = [IPAddress.Parse("10.3.0.37")],
            ["authserver1.antiwizard.net"] = [IPAddress.Parse("10.3.0.34")],
            ["authserver2.antiwizard.net"] = [IPAddress.Parse("10.3.0.36")]
        }), new DynamicResolver(NullLogger<DynamicResolver>.Instance));
        
        Firewall = parsedFirewall.ConvertToFirewall(ipGroups, policies, ruleCollectionGroups, dnsResolver, NullLoggerFactory.Instance.CreateLogger("")).Result;
        RuleProcessor = new RuleProcessor(dnsResolver, Firewall);
    }

    public Firewall Firewall { get; }
    public RuleProcessor RuleProcessor { get; }    

    public void Dispose()
    {
    }
}