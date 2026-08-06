using Shouldly;
using SoftwareComplianceChecker.Scanning.Platform;
using Xunit;

namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// Explorer is passed a quoted path rather than an escaped argument list, because it does not
/// follow the usual escaping conventions. These tests pin the validation that makes that safe.
/// </summary>
public sealed class ExplorerArgumentsTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_paths_are_rejected(string? path) =>
        ExplorerArguments.IsSafePath(path).ShouldBeFalse();

    [Fact]
    public void A_path_containing_a_quote_is_rejected()
    {
        // Windows paths cannot contain a double quote, so anything that does is either
        // corrupt or an attempt to break out of the quoting.
        ExplorerArguments.IsSafePath("C:\\Tools\\evil\".exe").ShouldBeFalse();
        ExplorerArguments.TryBuildSelectArguments("C:\\Tools\\evil\".exe", out _).ShouldBeFalse();
    }

    [Fact]
    public void A_path_containing_control_characters_is_rejected() =>
        ExplorerArguments.IsSafePath("C:\\Tools\\bad\u0000name.exe").ShouldBeFalse();

    [Fact]
    public void A_relative_path_is_rejected() =>
        // A relative path would resolve against the application's directory rather than the
        // one the user is looking at.
        ExplorerArguments.IsSafePath("Tools\\app.exe").ShouldBeFalse();

    [Fact]
    public void A_driveless_root_is_rejected() =>
        // Path.IsPathRooted would accept this, but Explorer cannot open it.
        ExplorerArguments.IsSafePath("\\folder\\app.exe").ShouldBeFalse();

    [Theory]
    [InlineData(@"C:\Tools\app.exe")]
    [InlineData(@"c:/Tools/app.exe")]
    [InlineData(@"\\fileserver\share\app.exe")]
    public void Drive_qualified_and_unc_paths_are_accepted(string path) =>
        ExplorerArguments.IsSafePath(path).ShouldBeTrue();

    [Fact]
    public void Select_arguments_quote_the_path()
    {
        ExplorerArguments.TryBuildSelectArguments(@"C:\Tools\My App\run.exe", out var arguments)
            .ShouldBeTrue();

        arguments.ShouldBe("/select,\"C:\\Tools\\My App\\run.exe\"");
    }

    [Fact]
    public void Open_arguments_quote_the_folder()
    {
        ExplorerArguments.TryBuildOpenArguments(@"C:\Program Files\Thing", out var arguments)
            .ShouldBeTrue();

        arguments.ShouldBe("\"C:\\Program Files\\Thing\"");
    }

    [Fact]
    public void Rejected_paths_produce_no_arguments()
    {
        ExplorerArguments.TryBuildSelectArguments("relative.exe", out var arguments).ShouldBeFalse();
        arguments.ShouldBeEmpty();
    }
}
