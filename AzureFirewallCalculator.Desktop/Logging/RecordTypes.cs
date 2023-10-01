using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace AzureFirewallCalculator.Desktop.Logging;

public record class LogData(LogLevel LogLevel, EventId EventId, KeyValuePair<string, object?>[] Values, Exception? Exception, string FormattedLog);