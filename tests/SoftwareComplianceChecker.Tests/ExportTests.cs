using System.Text.Json;
using Shouldly;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Models;
using SoftwareComplianceChecker.Export;
using Xunit;

namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// Export correctness, with particular attention to CSV quoting: software names and file
/// paths routinely contain commas, so a naive join corrupts the file.
/// </summary>
public sealed class ExportTests
{
    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("has,comma", "\"has,comma\"")]
    [InlineData("has\"quote", "\"has\"\"quote\"")]
    [InlineData("has\nnewline", "\"has\nnewline\"")]
    [InlineData("", "")]
    [InlineData(null, "")]
    public void Csv_fields_are_quoted_per_rfc_4180(string? input, string expected) =>
        CsvReportExporter.Escape(input).ShouldBe(expected);

    [Fact]
    public void Csv_contains_a_row_for_every_finding_plus_a_header()
    {
        var report = SampleReport.Create();

        var lines = new CsvReportExporter().Render(report)
            .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);

        lines.Length.ShouldBe(report.TotalChecks + 1);
        lines[0].ShouldStartWith("Section,Status,Name");
    }

    [Fact]
    public void Json_export_is_valid_and_carries_the_summary()
    {
        var report = SampleReport.Create();

        using var document = JsonDocument.Parse(new JsonReportExporter().Render(report));
        var root = document.RootElement;

        root.GetProperty("ComputerName").GetString().ShouldBe("WORKSTATION-01");

        var summary = root.GetProperty("Summary");
        summary.GetProperty("OverallResult").GetString().ShouldBe("FAIL");
        summary.GetProperty("FailCount").GetInt32().ShouldBe(report.FailCount);
        summary.GetProperty("TotalChecks").GetInt32().ShouldBe(report.TotalChecks);
    }

    [Fact]
    public void Html_export_encodes_values_rather_than_emitting_them_as_markup()
    {
        // Names come from the scanned machine and must never be trusted as markup.
        var report = SampleReport.Create() with
        {
            InstalledSoftware =
            [
                new ScanFinding
                {
                    Name = "<script>alert(1)</script>",
                    Status = ComplianceStatus.Fail,
                    Reason = "Software prohibited by policy.",
                    Section = FindingSection.InstalledSoftware,
                },
            ],
        };

        var html = new HtmlReportExporter().Render(report);

        html.ShouldNotContain("<script>alert(1)</script>");
        html.ShouldContain("&lt;script&gt;");
    }

    [Fact]
    public void Html_export_is_self_contained()
    {
        var html = new HtmlReportExporter().Render(SampleReport.Create());

        html.ShouldStartWith("<!DOCTYPE html>");
        html.ShouldContain("<style>");
        html.ShouldNotContain("<link ");
        html.ShouldNotContain("<script ");
    }

    [Fact]
    public void Summary_counts_include_the_windows_license_check()
    {
        var report = SampleReport.Create();

        report.TotalChecks.ShouldBe(report.InstalledSoftware.Count + report.PortableSoftware.Count + 1);
        report.PassCount.ShouldBe(report.AllFindings.Count(f => f.Status == ComplianceStatus.Pass));
        report.OverallResult.ShouldBe(ComplianceStatus.Fail);
    }

    [Fact]
    public void A_report_with_no_failures_passes_overall()
    {
        var clean = SampleReport.Create() with
        {
            License = SampleReport.Create().License with
            {
                Status = ComplianceStatus.Pass,
                Reason = "Clean.",
                KmsEvidence = [],
            },
            InstalledSoftware =
            [
                new ScanFinding
                {
                    Name = "Blender",
                    Status = ComplianceStatus.Pass,
                    Reason = "No matching compliance rule.",
                    Section = FindingSection.InstalledSoftware,
                },
            ],
            PortableSoftware = [],
        };

        clean.OverallResult.ShouldBe(ComplianceStatus.Pass);
        clean.FailCount.ShouldBe(0);
    }

    [Fact]
    public void Suggested_file_names_use_the_format_extension()
    {
        var service = new ReportExportService(
            [new HtmlReportExporter(), new CsvReportExporter(), new JsonReportExporter()]);

        var report = SampleReport.Create();

        service.SuggestFileName(report, ReportFormat.Html).ShouldEndWith(".html");
        service.SuggestFileName(report, ReportFormat.Csv).ShouldEndWith(".csv");
        service.SuggestFileName(report, ReportFormat.Json).ShouldEndWith(".json");
        service.SuggestFileName(report, ReportFormat.Html).ShouldContain("WORKSTATION-01");
    }

    [Fact]
    public void Registering_two_exporters_for_one_format_is_rejected() =>
        Should.Throw<ArgumentException>(() =>
            new ReportExportService([new CsvReportExporter(), new CsvReportExporter()]));
}
