using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace AzureFirewallCalculator.Desktop.Logging;

public class InMemoryLogger : ILogger
{
    public readonly static Channel<LogData> LogChannel = Channel.CreateUnbounded<LogData>(new UnboundedChannelOptions
    {
        SingleReader = true
    });

    private const int MaxLogCount = 100_000;

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        return null;
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        return true;
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
        {
            return;
        }

        var formattableValues = state switch
        {
            IReadOnlyList<KeyValuePair<string, object?>> v => v.ToArray(),
            _ => Array.Empty<KeyValuePair<string, object?>>()
        };
        LogChannel.Writer.TryWrite(new LogData(LogLevel: logLevel, EventId: eventId, Values: formattableValues, Exception: exception, FormattedLog: formatter(state, exception)));
    }
}