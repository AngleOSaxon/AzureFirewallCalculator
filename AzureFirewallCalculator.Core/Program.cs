using System.Net;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Core.Dns;
using PowershellSource = AzureFirewallCalculator.Core.PowershellSource;

var firewallExport = File.ReadAllText("./Data/firewall.json");
var parsedFirewall = System.Text.Json.JsonSerializer.Deserialize<PowershellSource.Firewall>(firewallExport);

var ipGroupExport = File.ReadAllText("./Data/IpGroups.json");
var ipGroups = System.Text.Json.JsonSerializer.Deserialize<PowershellSource.IpGroup[]>(ipGroupExport)!.ToDictionary(item => item.Id, StringComparer.CurrentCultureIgnoreCase);

var dnsResolver = new CombinedResolver(new StaticDnsResolver(TestDataSetup.GetStaticDns()), new DynamicResolver());
var firewall = parsedFirewall.ConvertToFirewall(ipGroups, dnsResolver);


var applicationRequest = new ApplicationRequest("10.0.0.1", "google.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443));

var processor = new RuleProcessor(dnsResolver, firewall);

// var networkResults = processor.ProcessNetworkRequest(networkRequest);

var applicationResults = await processor.ProcessApplicationRequest(applicationRequest);

var i = 1;