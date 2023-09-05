using System.Net;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Test;
using PowershellSource = AzureFirewallCalculator.Core.PowershellSource;

namespace AzureFirewallCalculator.Tests;

public class TestImportedData : IClassFixture<ImportedDataFixture>
{
    private readonly ImportedDataFixture importedDataFixture;

    public TestImportedData(ImportedDataFixture importedDataFixture)
    {
        this.importedDataFixture = importedDataFixture;
    }

    [Fact]
    public async Task TestApplicationRules()
    {
        var applicationRequest = new ApplicationRequest("10.10.0.1", "google.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443));

        var insecureUserToGoogle = await importedDataFixture.RuleProcessor.ProcessApplicationRequest(applicationRequest);
        Assert.True(insecureUserToGoogle.OrderBy(item => item.Priority).First().RuleAction == RuleAction.Allow);

        applicationRequest = new ApplicationRequest("10.10.10.1", "google.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443));
        var secureUserToGoogle = await importedDataFixture.RuleProcessor.ProcessApplicationRequest(applicationRequest);
        Assert.False(secureUserToGoogle.OrderBy(item => item.Priority).FirstOrDefault() != null);
    }
}