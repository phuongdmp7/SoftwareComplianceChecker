using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Text;
using Microsoft.Extensions.Logging;

namespace SoftwareComplianceChecker.App.Logging;

/// <summary>
/// Writes log entries to one file per day, named <c>yyyy-MM-dd.log</c>.
/// </summary>
/// <remarks>
/// Hand-rolled rather than taking a logging framework dependency: the requirement is a
/// date-named text file with retention, which is a small amount of code and keeps the
/// dependency list minimal.
/// </remarks>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentDictionary<string, FileLogger> loggers = new(StringComparer.Ordinal);
    private readonly object writeLock = new();
    private readonly string directory;
    private readonly LogLevel minimumLevel;

    /// <summary>Creates the provider and applies retention.</summary>
    /// <param name="directory">Directory to write log files into.</param>
    /// <param name="minimumLevel">Lowest level to record.</param>
    /// <param name="retentionDays">Days to keep log files. Zero or less disables deletion.</param>
    public FileLoggerProvider(string directory, LogLevel minimumLevel, int retentionDays)
    {
        this.directory = directory;
        this.minimumLevel = minimumLevel;

        Directory.CreateDirectory(directory);
        this.ApplyRetention(retentionDays);
    }

    /// <inheritdoc />
    public ILogger CreateLogger(string categoryName) =>
        this.loggers.GetOrAdd(categoryName, name => new FileLogger(this, name));

    /// <inheritdoc />
    public void Dispose() => this.loggers.Clear();

    private bool IsEnabled(LogLevel level) => level >= this.minimumLevel && level != LogLevel.None;

    private void Write(string message)
    {
        var path = Path.Combine(
            this.directory,
            $"{DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}.log");

        lock (this.writeLock)
        {
            try
            {
                File.AppendAllText(path, message + Environment.NewLine, Encoding.UTF8);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Logging must never take down a scan. There is nowhere left to report this.
            }
        }
    }

    private void ApplyRetention(int retentionDays)
    {
        if (retentionDays <= 0)
        {
            return;
        }

        try
        {
            var cutoff = DateTime.Now.AddDays(-retentionDays);

            foreach (var file in Directory.GetFiles(this.directory, "*.log"))
            {
                if (File.GetLastWriteTime(file) < cutoff)
                {
                    File.Delete(file);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Retention is housekeeping; failing it must not prevent logging.
        }
    }

    private sealed class FileLogger : ILogger
    {
        private readonly FileLoggerProvider provider;
        private readonly string category;

        public FileLogger(FileLoggerProvider provider, string category)
        {
            this.provider = provider;
            this.category = category;
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => this.provider.IsEnabled(logLevel);

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!this.IsEnabled(logLevel))
            {
                return;
            }

            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
            var shortCategory = this.category.Split('.').LastOrDefault() ?? this.category;

            var builder = new StringBuilder()
                .Append(timestamp)
                .Append(" [").Append(Describe(logLevel)).Append("] ")
                .Append(shortCategory).Append(": ")
                .Append(formatter(state, exception));

            if (exception is not null)
            {
                builder.AppendLine().Append(exception);
            }

            this.provider.Write(builder.ToString());
        }

        private static string Describe(LogLevel level) => level switch
        {
            LogLevel.Trace => "TRC",
            LogLevel.Debug => "DBG",
            LogLevel.Information => "INF",
            LogLevel.Warning => "WRN",
            LogLevel.Error => "ERR",
            LogLevel.Critical => "CRT",
            _ => "———",
        };
    }
}
