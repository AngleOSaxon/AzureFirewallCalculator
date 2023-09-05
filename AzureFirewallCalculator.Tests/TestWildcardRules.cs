using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Tests;

public class TestWildcardRules
{

    public static IEnumerable<object[]> SourceData()
    {
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new RuleIpRange(uint.MinValue, uint.MinValue) }, new string[] { "*.example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new ApplicationProtocolPort(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "foo.example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            true
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new RuleIpRange(uint.MinValue, uint.MinValue) }, new string[] { "*.example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new ApplicationProtocolPort(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            false
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new RuleIpRange(uint.MinValue, uint.MinValue) }, new string[] { "*.example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new ApplicationProtocolPort(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "foo.bar.example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            true
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new RuleIpRange(uint.MinValue, uint.MinValue) }, new string[] { "*.example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new ApplicationProtocolPort(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "example.com.foo", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            false
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new RuleIpRange(uint.MinValue, uint.MinValue) }, new string[] { "*example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new ApplicationProtocolPort(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            true
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new RuleIpRange(uint.MinValue, uint.MinValue) }, new string[] { "*example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new ApplicationProtocolPort(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "foo.example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            true
        };
    }

    [Theory]
    [MemberData(nameof(SourceData))]
    public void TestApplicationWildcardRules(ApplicationRule rule, ApplicationRequest request, bool shouldBeAllowed)
    {
        Assert.Equal(rule.Matches(request), shouldBeAllowed);
    }
}