using System.Diagnostics;
using Microsoft.Extensions.Logging;
using SoftwareComplianceChecker.Core.Abstractions;

namespace SoftwareComplianceChecker.Scanning.Platform;

/// <summary>
/// Opens Windows locations through the shell.
/// </summary>
public sealed class WindowsSystemLauncher : ISystemLauncher
{
    /// <summary>The Settings page listing installed applications on Windows 10 and 11.</summary>
    private const string InstalledAppsUri = "ms-settings:appsfeatures";

    private readonly IFileSystem fileSystem;
    private readonly ILogger<WindowsSystemLauncher> logger;

    /// <summary>Creates the launcher.</summary>
    /// <param name="fileSystem">Used to check that a path still exists before revealing it.</param>
    /// <param name="logger">Receives diagnostics.</param>
    public WindowsSystemLauncher(IFileSystem fileSystem, ILogger<WindowsSystemLauncher> logger)
    {
        this.fileSystem = fileSystem;
        this.logger = logger;
    }

    /// <inheritdoc />
    public LaunchOutcome OpenInstalledApplications()
    {
        if (TryStart(new ProcessStartInfo(InstalledAppsUri) { UseShellExecute = true }))
        {
            return LaunchOutcome.Success("Opened Windows installed apps settings.");
        }

        // Settings can be disabled by policy on managed machines, where the classic
        // Programs and Features applet is usually still available.
        if (TryStart(new ProcessStartInfo("control.exe", "appwiz.cpl") { UseShellExecute = true }))
        {
            return LaunchOutcome.Success("Opened Programs and Features.");
        }

        this.logger.LogWarning("Neither the Settings app nor Programs and Features could be opened.");

        return LaunchOutcome.Failure(
            "Windows would not open the installed apps screen. Open Settings, then Apps, then Installed apps.");
    }

    /// <inheritdoc />
    public LaunchOutcome RevealInFileExplorer(string? path)
    {
        if (!ExplorerArguments.IsSafePath(path))
        {
            return LaunchOutcome.Failure("That item has no usable location to open.");
        }

        if (this.fileSystem.FileExists(path!)
            && ExplorerArguments.TryBuildSelectArguments(path, out var selectArguments)
            && TryStart(new ProcessStartInfo("explorer.exe", selectArguments) { UseShellExecute = true }))
        {
            return LaunchOutcome.Success($"Opened {path} in File Explorer.");
        }

        // The file may have been removed since the scan. Its folder is still worth opening.
        var containingFolder = TryGetDirectory(path!);

        if (containingFolder is not null
            && this.fileSystem.DirectoryExists(containingFolder)
            && ExplorerArguments.TryBuildOpenArguments(containingFolder, out var openArguments)
            && TryStart(new ProcessStartInfo("explorer.exe", openArguments) { UseShellExecute = true }))
        {
            return LaunchOutcome.Success($"The file was not found. Opened {containingFolder} instead.");
        }

        this.logger.LogWarning("Could not reveal {Path} in File Explorer.", path);

        return LaunchOutcome.Failure($"Could not open {path}. It may have been moved or deleted.");
    }

    private bool TryStart(ProcessStartInfo startInfo)
    {
        try
        {
            using var process = Process.Start(startInfo);
            return true;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception
                                       or InvalidOperationException
                                       or System.IO.FileNotFoundException)
        {
            this.logger.LogDebug(ex, "Could not start {FileName}.", startInfo.FileName);
            return false;
        }
    }

    private static string? TryGetDirectory(string path)
    {
        try
        {
            return Path.GetDirectoryName(path);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
