using System.Globalization;
using System.Text;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Export;

/// <summary>
/// Renders a report as RFC 4180 comma-separated values.
/// </summary>
public sealed class CsvReportExporter : IReportExporter
{
    /// <summary>Characters that force a field to be quoted.</summary>
    private static readonly char[] QuotableCharacters = [',', '"', '\r', '\n'];

    /// <inheritdoc />
    public ReportFormat Format => ReportFormat.Csv;

    /// <inheritdoc />
    public string FileExtension => ".csv";

    /// <inheritdoc />
    public string Render(ComplianceReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var builder = new StringBuilder();

        builder.AppendLine("Section,Status,Name,Publisher,Version,Location,Category,Reason,MatchedRule");

        foreach (var finding in report.AllFindings)
        {
            builder.AppendLine(string.Join(',',
                Escape(finding.Section.ToString()),
                Escape(finding.Status.ToString().ToUpperInvariant()),
                Escape(finding.Name),
                Escape(finding.Publisher),
                Escape(finding.Version),
                Escape(finding.Location),
                Escape(finding.Category),
                Escape(finding.Reason),
                Escape(finding.MatchedRule)));
        }

        return builder.ToString();
    }

    /// <summary>
    /// Quotes a CSV field per RFC 4180.
    /// </summary>
    /// <remarks>
    /// Fields are quoted when they contain a comma, quote, or line break. Embedded quotes are
    /// doubled. Software names and file paths routinely contain commas, so this is load-bearing
    /// rather than defensive.
    /// </remarks>
    internal static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var needsQuoting = value.IndexOfAny(QuotableCharacters) >= 0;

        if (!needsQuoting)
        {
            return value;
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"");
    }
}
