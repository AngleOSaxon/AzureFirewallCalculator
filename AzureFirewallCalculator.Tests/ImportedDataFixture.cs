using System.Net;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Core.Dns;
using Microsoft.Extensions.Logging.Abstractions;
using PowershellSource = AzureFirewallCalculator.Core.PowershellSource;

namespace AzureFirewallCalculator.Tests;

public class ImportedDataFixture : IDisposable
{
    public ImportedDataFixture()
    {
        var firewallExport = File.ReadAllText("./PowershellData/firewall.json");
        var parsedFirewall = System.Text.Json.JsonSerializer.Deserialize<PowershellSource.Firewall>(firewallExport);

        var ipGroupExport = File.ReadAllText("./PowershellData/IpGroups.json");
        var ipGroups = System.Text.Json.JsonSerializer.Deserialize<PowershellSource.IpGroup[]>(ipGroupExport)!.ToDictionary(item => item.Id, StringComparer.CurrentCultureIgnoreCase);

        var dnsResolver = new CachingResolver(new StaticDnsResolver(new Dictionary<string, IPAddress[]>
        {
            ["sqlserver.antiwizard.net"] = [IPAddress.Parse("10.3.0.33")],
            ["mysql.antiwizard.net"] = [IPAddress.Parse("10.3.0.35")],
            ["cosmosdb.antiwizard.net"] = [IPAddress.Parse("10.3.0.37")],
            ["authserver1.antiwizard.net"] = [IPAddress.Parse("10.3.0.34")],
            ["authserver2.antiwizard.net"] = [IPAddress.Parse("10.3.0.36")]
        }), new DynamicResolver(NullLogger<DynamicResolver>.Instance));
        
        Firewall = parsedFirewall.ConvertToFirewall(ipGroups, dnsResolver, NullLoggerFactory.Instance.CreateLogger("")).Result;
        RuleProcessor = new RuleProcessor(dnsResolver, Firewall);
    }

    public Firewall Firewall { get; }
    public RuleProcessor RuleProcessor { get; }    

    public void Dispose()
    {
    }
}