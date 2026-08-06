using System.Globalization;
using System.Text;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Export;

/// <summary>
/// Writes reports to disk in a requested format.
/// </summary>
public sealed class ReportExportService : IReportExportService
{
    private readonly IReadOnlyDictionary<ReportFormat, IReportExporter> exporters;

    /// <summary>Creates the service over the available exporters.</summary>
    /// <param name="exporters">One exporter per supported format.</param>
    /// <exception cref="ArgumentException">Two exporters claim the same format.</exception>
    public ReportExportService(IEnumerable<IReportExporter> exporters)
    {
        ArgumentNullException.ThrowIfNull(exporters);

        var map = new Dictionary<ReportFormat, IReportExporter>();

        foreach (var exporter in exporters)
        {
            if (!map.TryAdd(exporter.Format, exporter))
            {
                throw new ArgumentException(
                    $"More than one exporter is registered for {exporter.Format}.", nameof(exporters));
            }
        }

        this.exporters = map;
    }

    /// <inheritdoc />
    public async Task ExportAsync(
        ComplianceReport report,
        ReportFormat format,
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var exporter = this.Resolve(format);
        var content = exporter.Render(report);

        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // UTF-8 with a BOM so Excel opens the CSV with the correct encoding; without it,
        // non-ASCII publisher names are mangled on open.
        var encoding = format == ReportFormat.Csv ? new UTF8Encoding(true) : new UTF8Encoding(false);

        await File.WriteAllTextAsync(filePath, content, encoding, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public string SuggestFileName(ComplianceReport report, ReportFormat format)
    {
        ArgumentNullException.ThrowIfNull(report);

        var exporter = this.Resolve(format);
        var timestamp = report.ScanTime.ToString("yyyy-MM-dd_HHmm", CultureInfo.InvariantCulture);
        var machine = Sanitize(report.ComputerName);

        return $"compliance_{machine}_{timestamp}{exporter.FileExtension}";
    }

    private IReportExporter Resolve(ReportFormat format)
    {
        if (this.exporters.TryGetValue(format, out var exporter))
        {
            return exporter;
        }

        throw new NotSupportedException($"No exporter is registered for the {format} format.");
    }

    private static string Sanitize(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var builder = new StringBuilder(value.Length);

        foreach (var c in value)
        {
            builder.Append(invalid.Contains(c) ? '_' : c);
        }

        return builder.ToString();
    }
}
