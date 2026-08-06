using System.Globalization;
using System.Net;
using System.Text;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Export;

/// <summary>
/// Renders a report as a self-contained dark-themed HTML document.
/// </summary>
/// <remarks>
/// All styling is inline so the file can be mailed or archived as a single artifact with no
/// external assets. Every value is HTML-encoded: software names and file paths come from the
/// scanned machine and must never be treated as markup.
/// </remarks>
public sealed class HtmlReportExporter : IReportExporter
{
    /// <inheritdoc />
    public ReportFormat Format => ReportFormat.Html;

    /// <inheritdoc />
    public string FileExtension => ".html";

    /// <inheritdoc />
    public string Render(ComplianceReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var builder = new StringBuilder();

        builder.AppendLine("<!DOCTYPE html>");
        builder.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\">");
        builder.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        builder.AppendLine($"<title>Compliance Report - {E(report.ComputerName)}</title>");
        builder.AppendLine(Styles);
        builder.AppendLine("</head><body><div class=\"page\">");

        AppendHeader(builder, report);
        AppendSummary(builder, report);
        AppendLicense(builder, report);
        AppendFindings(builder, "Installed Software", report.InstalledSoftware);
        AppendFindings(builder, "Portable Software", report.PortableSoftware, emptyMessage:
            "No prohibited portable software was found in the configured folders.");
        AppendWarnings(builder, report);

        builder.AppendLine("</div></body></html>");

        return builder.ToString();
    }

    private static void AppendHeader(StringBuilder builder, ComplianceReport report)
    {
        builder.AppendLine("<header>");
        builder.AppendLine("<h1>Software Compliance Report</h1>");
        builder.AppendLine("<dl class=\"meta\">");
        AppendMeta(builder, "Computer", report.ComputerName);
        AppendMeta(builder, "User", report.UserName);
        AppendMeta(builder, "Operating system", report.OperatingSystem);
        AppendMeta(builder, "Scan time", report.ScanTime.ToString("f", CultureInfo.InvariantCulture));
        AppendMeta(builder, "Duration", $"{report.Duration.TotalSeconds:F2} s");
        builder.AppendLine("</dl></header>");
    }

    private static void AppendSummary(StringBuilder builder, ComplianceReport report)
    {
        var overall = report.OverallResult;
        var overallClass = overall == ComplianceStatus.Pass ? "pass" : "fail";

        builder.AppendLine("<section class=\"cards\">");
        builder.AppendLine($"<div class=\"card {overallClass}\"><span class=\"label\">Overall result</span>" +
                           $"<span class=\"value\">{StatusText(overall)}</span></div>");
        builder.AppendLine($"<div class=\"card\"><span class=\"label\">Total checks</span>" +
                           $"<span class=\"value\">{report.TotalChecks}</span></div>");
        builder.AppendLine($"<div class=\"card pass\"><span class=\"label\">Passed</span>" +
                           $"<span class=\"value\">{report.PassCount}</span></div>");
        builder.AppendLine($"<div class=\"card fail\"><span class=\"label\">Failed</span>" +
                           $"<span class=\"value\">{report.FailCount}</span></div>");
        builder.AppendLine("</section>");
    }

    private static void AppendLicense(StringBuilder builder, ComplianceReport report)
    {
        var license = report.License;
        var evidence = license.Evidence;

        builder.AppendLine("<section><h2>Windows License</h2>");
        builder.AppendLine("<dl class=\"meta\">");
        AppendMeta(builder, "Edition", evidence.Edition);
        AppendMeta(builder, "Product name", evidence.ProductName);
        AppendMeta(builder, "Version", evidence.Version);
        AppendMeta(builder, "Build", evidence.BuildNumber);
        AppendMeta(builder, "License status", evidence.LicenseStatus);
        AppendMeta(builder, "Activation channel", evidence.ProductKeyChannel);
        AppendMeta(builder, "License description", evidence.LicenseDescription);
        AppendMeta(builder, "Partial product key", evidence.PartialProductKey);
        AppendMeta(builder, "Activation type", license.ActivationType.ToString());
        AppendMeta(builder, "OEM BIOS key present", evidence.OemBiosKeyPresent ? "Yes" : "No");
        AppendMeta(builder, "KMS host", evidence.KmsServerName);
        builder.AppendLine("</dl>");

        builder.AppendLine($"<p class=\"verdict {(license.Status == ComplianceStatus.Pass ? "pass" : "fail")}\">" +
                           $"{StatusText(license.Status)} &mdash; {E(license.Reason)}</p>");

        if (license.KmsEvidence.Count > 0)
        {
            builder.AppendLine("<h3>KMS evidence</h3><ul class=\"evidence\">");
            foreach (var item in license.KmsEvidence)
            {
                builder.AppendLine($"<li>{E(item)}</li>");
            }

            builder.AppendLine("</ul>");
        }

        builder.AppendLine("</section>");
    }

    private static void AppendFindings(
        StringBuilder builder,
        string title,
        IReadOnlyList<ScanFinding> findings,
        string? emptyMessage = null)
    {
        builder.AppendLine($"<section><h2>{E(title)} <span class=\"count\">{findings.Count}</span></h2>");

        if (findings.Count == 0)
        {
            builder.AppendLine($"<p class=\"empty\">{E(emptyMessage ?? "Nothing was found.")}</p></section>");
            return;
        }

        builder.AppendLine("<table><thead><tr>");
        builder.AppendLine("<th>Status</th><th>Name</th><th>Publisher</th><th>Version</th>" +
                           "<th>Location</th><th>Reason</th>");
        builder.AppendLine("</tr></thead><tbody>");

        foreach (var finding in findings)
        {
            var rowClass = finding.Status == ComplianceStatus.Pass ? "pass" : "fail";

            builder.AppendLine($"<tr class=\"{rowClass}\">");
            builder.AppendLine($"<td><span class=\"pill {rowClass}\">{StatusText(finding.Status)}</span></td>");
            builder.AppendLine($"<td>{E(finding.Name)}</td>");
            builder.AppendLine($"<td>{E(finding.Publisher)}</td>");
            builder.AppendLine($"<td>{E(finding.Version)}</td>");
            builder.AppendLine($"<td class=\"path\">{E(finding.Location)}</td>");
            builder.AppendLine($"<td>{E(finding.Reason)}</td>");
            builder.AppendLine("</tr>");
        }

        builder.AppendLine("</tbody></table></section>");
    }

    private static void AppendWarnings(StringBuilder builder, ComplianceReport report)
    {
        if (report.Warnings.Count == 0)
        {
            return;
        }

        builder.AppendLine("<section><h2>Scan notes</h2><ul class=\"evidence\">");

        foreach (var warning in report.Warnings)
        {
            builder.AppendLine($"<li>{E(warning)}</li>");
        }

        builder.AppendLine("</ul></section>");
    }

    private static void AppendMeta(StringBuilder builder, string label, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        builder.AppendLine($"<div><dt>{E(label)}</dt><dd>{E(value)}</dd></div>");
    }

    private static string StatusText(ComplianceStatus status) =>
        status == ComplianceStatus.Pass ? "PASS" : "FAIL";

    private static string E(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    private const string Styles = """
        <style>
          :root {
            --bg: #12141a; --surface: #1b1e26; --border: #2b2f3a;
            --text: #e6e8ee; --muted: #9aa1b1;
            --pass: #3fb950; --fail: #f85149;
          }
          * { box-sizing: border-box; }
          body {
            margin: 0; background: var(--bg); color: var(--text);
            font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
            font-size: 14px; line-height: 1.5;
          }
          .page { max-width: 1200px; margin: 0 auto; padding: 32px 24px 64px; }
          h1 { font-size: 24px; margin: 0 0 16px; font-weight: 600; }
          h2 { font-size: 17px; margin: 40px 0 12px; font-weight: 600; }
          h3 { font-size: 14px; margin: 20px 0 8px; color: var(--muted); font-weight: 600; }
          .count { color: var(--muted); font-weight: 400; font-size: 14px; }
          .meta { display: flex; flex-wrap: wrap; gap: 8px 32px; margin: 0; }
          .meta div { min-width: 180px; }
          .meta dt { color: var(--muted); font-size: 12px; }
          .meta dd { margin: 0; font-variant-numeric: tabular-nums; }
          .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                   gap: 12px; margin: 24px 0 8px; }
          .card { background: var(--surface); border: 1px solid var(--border);
                  border-radius: 8px; padding: 16px; display: flex; flex-direction: column; gap: 6px; }
          .card .label { color: var(--muted); font-size: 12px; text-transform: uppercase;
                         letter-spacing: .04em; }
          .card .value { font-size: 26px; font-weight: 600; }
          .card.pass .value { color: var(--pass); }
          .card.fail .value { color: var(--fail); }
          table { width: 100%; border-collapse: collapse; background: var(--surface);
                  border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
          th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--border);
                   vertical-align: top; }
          th { color: var(--muted); font-size: 12px; text-transform: uppercase;
               letter-spacing: .04em; font-weight: 600; }
          tbody tr:last-child td { border-bottom: none; }
          tr.fail td { background: rgba(248, 81, 73, .06); }
          .path { color: var(--muted); font-family: Consolas, "Courier New", monospace;
                  font-size: 12px; word-break: break-all; }
          .pill { display: inline-block; padding: 2px 8px; border-radius: 999px;
                  font-size: 11px; font-weight: 700; letter-spacing: .04em; }
          .pill.pass { background: rgba(63, 185, 80, .15); color: var(--pass); }
          .pill.fail { background: rgba(248, 81, 73, .15); color: var(--fail); }
          .verdict { font-weight: 600; margin: 16px 0 0; }
          .verdict.pass { color: var(--pass); }
          .verdict.fail { color: var(--fail); }
          .evidence { margin: 8px 0 0; padding-left: 20px; color: var(--muted); }
          .evidence li { margin-bottom: 4px; }
          .empty { color: var(--muted); }
        </style>
        """;
}
