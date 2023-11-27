using System.Net;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Core.Dns;
using PowershellSource = AzureFirewallCalculator.Core.PowershellSource;

namespace AzureFirewallCalculator.Tests;

public class TestImportedData : IClassFixture<ImportedDataFixture>
{
    private readonly ImportedDataFixture importedDataFixture;

    public static IEnumerable<object[]> ApplicationRuleTests()
    {
        yield return new object[] { new ApplicationRequest("10.10.0.1", "google.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)) };
        yield return new object[] { new ApplicationRequest("10.10.10.1", "sqlserver.antiwizard.net", new ApplicationProtocolPort(ApplicationProtocol.Mssql, 1433)) };
        yield return new object[] { new ApplicationRequest("10.2.0.55", "sqlserver.antiwizard.net", new ApplicationProtocolPort(ApplicationProtocol.Mssql, 1433)) };
        yield return new object[] { new ApplicationRequest("10.10.0.55", "reddit.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)) };
        yield return new object[] { new ApplicationRequest("10.2.1.55", "cosmosdb.antiwizard.net", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)) };
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

    public TestImportedData(ImportedDataFixture importedDataFixture)
    {
        this.importedDataFixture = importedDataFixture;
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
    public void TestAllowNetworkRules(NetworkRequest request)
    {
        var result = importedDataFixture.RuleProcessor.ProcessNetworkRequest(request);
        Assert.True(result.OrderBy(item => item.Priority).First().RuleAction == RuleAction.Allow);
    }
}