using Shouldly;
using SoftwareComplianceChecker.Core;
using Xunit;

namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// The title bar reports which build produced a report, so the version has to come out clean
/// whichever assembly attribute it was read from.
/// </summary>
public sealed class ApplicationVersionTests
{
    [Theory]
    [InlineData("1.0.3", "1.0.3")]
    [InlineData("1.0.3.0", "1.0.3")]          // four-part file version, redundant zero revision
    [InlineData("1.0.3.4", "1.0.3.4")]        // a real revision is kept
    [InlineData("1.0.3+a1b2c3d", "1.0.3")]    // SourceLink build metadata
    [InlineData("  1.0.3  ", "1.0.3")]
    [InlineData("2.1.0-beta.2", "2.1.0-beta.2")]
    public void Versions_are_normalised_for_display(string raw, string expected) =>
        ApplicationVersion.Normalize(raw).ShouldBe(expected);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void An_absent_version_normalises_to_null(string? raw) =>
        ApplicationVersion.Normalize(raw).ShouldBeNull();

    [Fact]
    public void The_title_carries_the_version() =>
        ApplicationVersion.BuildTitle("Software Compliance Checker", "1.0.3")
            .ShouldBe("Software Compliance Checker (1.0.3)");

    [Fact]
    public void The_title_omits_an_unknown_version() =>
        // Better a plain title than one reading "(unknown)".
        ApplicationVersion.BuildTitle("Software Compliance Checker", null)
            .ShouldBe("Software Compliance Checker");
}
