using System.Net;
using System.Text.Json;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Core.Dns;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit.Sdk;
using PowershellSource = AzureFirewallCalculator.Core.PowershellSource;

namespace AzureFirewallCalculator.Tests;

public class TestImportedData : IClassFixture<ImportedDataFixture>, IClassFixture<ImportedDataPolicyFixture>
{
    private readonly ImportedDataFixture importedDataFixture;
    private readonly ImportedDataPolicyFixture importedDataPolicyFixture;

    public static IEnumerable<object[]> ApplicationRuleTests()
    {
        yield return new object[] { new ApplicationRequest("10.10.0.1", "google.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)) };
        yield return new object[] { new ApplicationRequest("10.10.10.1", "sqlserver.antiwizard.net", new ApplicationProtocolPort(ApplicationProtocol.Mssql, 1433)) };
        yield return new object[] { new ApplicationRequest("10.2.0.55", "sqlserver.antiwizard.net", new ApplicationProtocolPort(ApplicationProtocol.Mssql, 1433)) };
        yield return new object[] { new ApplicationRequest("10.10.0.55", "reddit.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)) };
        yield return new object[] { new ApplicationRequest("10.2.1.55", "cosmosdb.antiwizard.net", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)) };
        yield return new object[] { new ApplicationRequest("10.2.1.55", "cosmosdb.antiwizard.net", new ApplicationProtocolPort(ApplicationProtocol.Https, null)) };
    }

    public static IEnumerable<object[]> NetworkRuleTests()
    {
        yield return new object[] { new NetworkRequest("10.10.0.1", "10.2.0.55", 88, NetworkProtocols.TCP) };
        yield return new object[] { new NetworkRequest("10.10.0.1", "10.2.0.24", 1500, NetworkProtocols.TCP) };
        yield return new object[] { new NetworkRequest("10.10.10.1", "10.2.0.24", 1495, NetworkProtocols.TCP) };
        yield return new object[] { new NetworkRequest("10.10.10.1", "10.3.0.35", 3306, NetworkProtocols.TCP) };
        yield return new object[] { new NetworkRequest("10.10.10.1", "10.2.0.24", ushort.MaxValue, NetworkProtocols.TCP) };
        yield return new object[] { new NetworkRequest("10.1.0.34", "10.3.0.35", 3306, NetworkProtocols.TCP) };
        yield return new object[] { new NetworkRequest("10.1.0.34", "10.2.0.35", ushort.MaxValue, NetworkProtocols.TCP) };
        yield return new object[] { new NetworkRequest("10.1.0.34", "10.2.0.35", ushort.MinValue, NetworkProtocols.TCP) };

        yield return new object[] { new NetworkRequest("10.2.0.5", "13.65.211.125", 443, NetworkProtocols.TCP) };
        yield return new object[] { new NetworkRequest("10.2.0.5", "13.66.141.155", 443, NetworkProtocols.TCP) };

        yield return new object[] { new NetworkRequest("10.2.0.5", "13.66.141.155", null, NetworkProtocols.TCP) };
    }

    public static IEnumerable<object[]> NetworkRulePolicyTests_Allowed()
    {
        yield return new object[] { new NetworkRequest("10.0.2.1", "10.0.2.55", 445, NetworkProtocols.TCP), "Test" };
        yield return new object[] { new NetworkRequest("10.0.0.0", "10.0.1.0", 22, NetworkProtocols.TCP), "Test" };
    }

    public static IEnumerable<object[]> NetworkRulePolicyTests_Denied()
    {
        yield return new object[] { new NetworkRequest("10.0.2.1", "10.0.2.55", 88, NetworkProtocols.UDP) };
    }

    public TestImportedData(ImportedDataFixture importedDataFixture, ImportedDataPolicyFixture importedDataPolicyFixture)
    {
        this.importedDataFixture = importedDataFixture;
        this.importedDataPolicyFixture = importedDataPolicyFixture;
    }

    [Theory]
    [MemberData(nameof(ApplicationRuleTests))]
    public async Task TestAllowApplicationRules(ApplicationRequest applicationRequest)
    {
        var result = await importedDataFixture.RuleProcessor.ProcessApplicationRequest(applicationRequest);
        Assert.True(result.OrderBy(item => item.Priority).First().RuleAction == RuleAction.Allow);
    }

    [Theory]
    [MemberData(nameof(NetworkRuleTests))]
    public async Task TestAllowNetworkRules(NetworkRequest request)
    {
        var result = await importedDataFixture.RuleProcessor.ProcessNetworkRequest(request);
        Assert.True(result.OrderBy(item => item.Priority).First().RuleAction == RuleAction.Allow);
    }

    [Theory]
    [MemberData(nameof(NetworkRulePolicyTests_Allowed))]
    public async Task TestAllowNetworkRules_Policy(NetworkRequest request, string matchedRuleName)
    {
        var result = await importedDataPolicyFixture.RuleProcessor.ProcessNetworkRequest(request);
        Assert.True(result.First().RuleAction == RuleAction.Allow);
        var ruleName = result.First() switch
        {
            NetworkProcessingResponse networkResult => networkResult.MatchedRules.First().Rule.Name,
            ApplicationProcessingResponse applicationResult => applicationResult.MatchedRules.First().Rule.Name,
            _ => throw new InvalidOperationException($"Unknown response result type: {result.First().GetType().Name}"),
        };
        Assert.Equal(matchedRuleName, ruleName);
    }

    [Theory]
    [MemberData(nameof(NetworkRulePolicyTests_Denied))]
    public async Task TestDenyNetworkRules_Policy(NetworkRequest request)
    {
        var result = await importedDataPolicyFixture.RuleProcessor.ProcessNetworkRequest(request);
        Assert.Empty(result);
    }
}