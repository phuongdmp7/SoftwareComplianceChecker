using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Core.Abstractions;

/// <summary>Report output format.</summary>
public enum ReportFormat
{
    /// <summary>Self-contained HTML document.</summary>
    Html = 0,

    /// <summary>Comma-separated values, RFC 4180.</summary>
    Csv = 1,

    /// <summary>JSON document.</summary>
    Json = 2,
}

/// <summary>
/// Renders a <see cref="ComplianceReport"/> in one output format.
/// </summary>
public interface IReportExporter
{
    /// <summary>The format this exporter produces.</summary>
    ReportFormat Format { get; }

    /// <summary>Conventional file extension, including the leading dot.</summary>
    string FileExtension { get; }

    /// <summary>Renders the report to a string.</summary>
    /// <param name="report">The report to render.</param>
    string Render(ComplianceReport report);
}

/// <summary>
/// Writes reports to disk in a requested format.
/// </summary>
public interface IReportExportService
{
    /// <summary>Renders a report and writes it to a file.</summary>
    /// <param name="report">The report to export.</param>
    /// <param name="format">Output format.</param>
    /// <param name="filePath">Destination path.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    Task ExportAsync(
        ComplianceReport report,
        ReportFormat format,
        string filePath,
        CancellationToken cancellationToken = default);

    /// <summary>Suggests a file name for a report in the given format.</summary>
    /// <param name="report">The report the name describes.</param>
    /// <param name="format">Output format.</param>
    string SuggestFileName(ComplianceReport report, ReportFormat format);
}
