using System.Text.Json;
using System.Text.Json.Serialization;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Export;

/// <summary>
/// Renders a report as JSON.
/// </summary>
public sealed class JsonReportExporter : IReportExporter
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <inheritdoc />
    public ReportFormat Format => ReportFormat.Json;

    /// <inheritdoc />
    public string FileExtension => ".json";

    /// <inheritdoc />
    public string Render(ComplianceReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var document = new
        {
            report.ComputerName,
            report.UserName,
            report.OperatingSystem,
            ScanTime = report.ScanTime.ToString("O"),
            DurationSeconds = Math.Round(report.Duration.TotalSeconds, 2),
            Summary = new
            {
                OverallResult = report.OverallResult.ToString().ToUpperInvariant(),
                report.TotalChecks,
                report.PassCount,
                report.FailCount,
            },
            WindowsLicense = new
            {
                report.License.Status,
                report.License.Reason,
                report.License.ActivationType,
                report.License.Evidence.Edition,
                report.License.Evidence.ProductName,
                report.License.Evidence.Version,
                report.License.Evidence.BuildNumber,
                report.License.Evidence.LicenseStatus,
                report.License.Evidence.ProductKeyChannel,
                report.License.Evidence.LicenseDescription,
                report.License.Evidence.PartialProductKey,
                report.License.Evidence.OemBiosKeyPresent,
                report.License.Evidence.KmsServerName,
                report.License.Evidence.KmsServerPort,
                report.License.KmsEvidence,
            },
            report.InstalledSoftware,
            report.PortableSoftware,
            report.Warnings,
        };

        return JsonSerializer.Serialize(document, SerializerOptions);
    }
}
