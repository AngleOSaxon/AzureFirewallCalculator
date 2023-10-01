using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace AzureFirewallCalculator.Desktop.Logging;

public class InMemoryLogReader
{
    public InMemoryLogReader(ChannelReader<LogData> channelReader, CancellationToken? cancellationToken)
    {
        ChannelReader = channelReader;
        CancellationToken = cancellationToken ?? CancellationToken.None;
        _ = HandleLogs();
    }

    public ChannelReader<LogData> ChannelReader { get; }
    public CancellationToken CancellationToken { get; }

    private const int LogCount = 100_000;
    private int currentLogCounter = 0;
    private readonly LogData[] logs = new LogData[LogCount];

    public async Task HandleLogs()
    {
        while (await ChannelReader.WaitToReadAsync() && !CancellationToken.IsCancellationRequested)
        {
            while (ChannelReader.TryRead(out var log) && !CancellationToken.IsCancellationRequested)
            {
                currentLogCounter = (currentLogCounter + 1) % LogCount;
                logs[currentLogCounter] = log;
                LogPosted?.Invoke(this, log);
            }
        }
    }

    public ReadOnlyMemory<LogData> GetLogView(int from, int count)
    {
        return logs.AsMemory(0, currentLogCounter < count ? currentLogCounter : count);
    }

    public EventHandler<LogData>? LogPosted;
}