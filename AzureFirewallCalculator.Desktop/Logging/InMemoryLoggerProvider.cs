using Microsoft.Extensions.Logging;

namespace AzureFirewallCalculator.Desktop.Logging;

public class InMemoryLoggerProvider : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName)
    {
        // TODO: Category name
        return new InMemoryLogger();
    }

    public void Dispose()
    {
    }
}