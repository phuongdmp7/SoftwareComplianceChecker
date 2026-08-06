namespace SoftwareComplianceChecker.Core.Abstractions;

/// <summary>
/// The result of asking the operating system to open something.
/// </summary>
/// <param name="Succeeded">Whether the shell accepted the request.</param>
/// <param name="Message">Text suitable for the status bar, explaining what happened.</param>
public sealed record LaunchOutcome(bool Succeeded, string Message)
{
    /// <summary>A successful launch.</summary>
    /// <param name="message">What was opened.</param>
    public static LaunchOutcome Success(string message) => new(true, message);

    /// <summary>A failed launch.</summary>
    /// <param name="message">Why it failed.</param>
    public static LaunchOutcome Failure(string message) => new(false, message);
}

/// <summary>
/// Opens operating system locations on the user's behalf.
/// </summary>
/// <remarks>
/// The application never uninstalls anything itself. Removing software is the user's
/// decision and is carried out through Windows' own interface, so this only opens the
/// relevant screen or folder.
/// </remarks>
public interface ISystemLauncher
{
    /// <summary>
    /// Opens the Windows screen where installed applications can be uninstalled.
    /// </summary>
    LaunchOutcome OpenInstalledApplications();

    /// <summary>
    /// Opens File Explorer showing the containing folder with the item selected.
    /// </summary>
    /// <param name="path">Full path to the file or folder to reveal.</param>
    /// <returns>
    /// Success when Explorer was launched. If the file has since been moved or deleted, the
    /// containing folder is opened instead, because that is still useful.
    /// </returns>
    LaunchOutcome RevealInFileExplorer(string? path);
}
