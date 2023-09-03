using System.Net;
using AzureFirewallCalculator.Core;
using PowershellSource = AzureFirewallCalculator.Core.PowershellSource;

var firewallExport = File.ReadAllText("./Data/firewall.json");
var parsedFirewall = System.Text.Json.JsonSerializer.Deserialize<PowershellSource.Firewall>(firewallExport);

var ipGroupExport = File.ReadAllText("./Data/IpGroups.json");
var ipGroups = System.Text.Json.JsonSerializer.Deserialize<PowershellSource.IpGroup[]>(ipGroupExport)!.ToDictionary(item => item.Id, StringComparer.CurrentCultureIgnoreCase);

var firewall = parsedFirewall.ConvertToFirewall(ipGroups);


var networkRequest = new NetworkRequest("", "", 155, NetworkProtocols.TCP);

var networkRequestSeed = new List<(int, string, RuleAction, NetworkRule[])>();
var networkRequestResults = firewall.NetworkRuleCollections.Aggregate(networkRequestSeed, (accumulator, collection) => 
{
    var matches = collection.GetMatches(networkRequest);
    if (matches.Any())
    {
        accumulator.Add((collection.Priority, collection.Name, collection.RuleAction, matches));
    }
    return accumulator;
});

var applicationRequest = new ApplicationRequest("", "", new ApplicationProtocolPort(ApplicationProtocol.Https, 443));

var seed = new List<(int, string, RuleAction, ApplicationRule[])>();
var results = firewall.ApplicationRuleCollections.Aggregate(seed, (accumulator, collection) => 
{
    var matches = collection.GetMatches(applicationRequest);
    if (matches.Any())
    {
        accumulator.Add((collection.Priority, collection.Name, collection.RuleAction, matches));
    }
    return accumulator;
});


//var results = rules.Where(item => item.DetermineAction(source, destination, destinationPort, NetworkProtocols.UDP) == RuleActions.Allow).ToList();

var i = 1;