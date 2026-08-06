using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Export;
using Xunit;

namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// Regenerates the committed sample reports from the fixture.
/// </summary>
/// <remarks>
/// The samples are produced by the real exporters rather than written by hand, so they cannot
/// drift away from what the application actually emits. Running the test suite refreshes them.
/// </remarks>
public sealed class SampleGenerationTests
{
    [Fact]
    public void Sample_reports_are_regenerated()
    {
        var samplesDirectory = LocateSamplesDirectory();

        if (samplesDirectory is null)
        {
            // Running outside a source checkout, for example from a packaged test run.
            return;
        }

        Directory.CreateDirectory(samplesDirectory);

        var report = SampleReport.Create();

        var exporters = new IReportExporter[]
        {
            new HtmlReportExporter(),
            new CsvReportExporter(),
            new JsonReportExporter(),
        };

        foreach (var exporter in exporters)
        {
            var path = Path.Combine(samplesDirectory, "sample-report" + exporter.FileExtension);
            File.WriteAllText(path, exporter.Render(report));

            Assert.True(File.Exists(path));
        }
    }

    private static string? LocateSamplesDirectory()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            // The repository root is the directory holding the solution file.
            if (directory.GetFiles("*.sln").Length > 0)
            {
                return Path.Combine(directory.FullName, "samples");
            }

            directory = directory.Parent;
        }

        return null;
    }
}
