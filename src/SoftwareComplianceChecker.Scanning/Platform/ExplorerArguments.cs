namespace SoftwareComplianceChecker.Scanning.Platform;

/// <summary>
/// Builds the command line used to reveal a path in File Explorer.
/// </summary>
/// <remarks>
/// <para>
/// Separated from the launcher so the argument construction, which is the part that can go
/// wrong, is unit testable without starting a process.
/// </para>
/// <para>
/// Explorer does not follow the usual command-line escaping conventions, so the path is
/// passed as a quoted string rather than through an argument list. Windows paths cannot
/// contain a double quote, and <see cref="TryBuildSelectArguments"/> rejects anything that
/// does, so a path taken from a scan cannot break out of the quoting.
/// </para>
/// </remarks>
public static class ExplorerArguments
{
    /// <summary>
    /// Builds the <c>/select</c> arguments that open a folder with one item highlighted.
    /// </summary>
    /// <param name="path">Full path to reveal.</param>
    /// <param name="arguments">The resulting command line, when the path is usable.</param>
    /// <returns><see langword="true"/> when <paramref name="path"/> can safely be revealed.</returns>
    public static bool TryBuildSelectArguments(string? path, out string arguments)
    {
        arguments = string.Empty;

        if (!IsSafePath(path))
        {
            return false;
        }

        arguments = $"/select,\"{path}\"";
        return true;
    }

    /// <summary>
    /// Builds the arguments that open a folder without selecting anything.
    /// </summary>
    /// <param name="path">Folder to open.</param>
    /// <param name="arguments">The resulting command line, when the path is usable.</param>
    /// <returns><see langword="true"/> when <paramref name="path"/> can safely be opened.</returns>
    public static bool TryBuildOpenArguments(string? path, out string arguments)
    {
        arguments = string.Empty;

        if (!IsSafePath(path))
        {
            return false;
        }

        arguments = $"\"{path}\"";
        return true;
    }

    /// <summary>
    /// Whether a path is usable as an Explorer argument.
    /// </summary>
    /// <param name="path">Path to check.</param>
    /// <remarks>
    /// <para>
    /// Requires a drive-qualified or UNC path and rejects quotes and control characters.
    /// Relative paths are refused because they would resolve against the application's
    /// directory rather than the one the user is looking at.
    /// </para>
    /// <para>
    /// The check is written out rather than delegated to <see cref="Path.IsPathRooted(string)"/>
    /// for two reasons: that method accepts driveless roots such as <c>\folder</c>, which
    /// Explorer cannot open, and its answer depends on the host operating system, which would
    /// make this logic untestable anywhere but Windows.
    /// </para>
    /// </remarks>
    public static bool IsSafePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        if (path.Contains('"', StringComparison.Ordinal) || path.Any(char.IsControl))
        {
            return false;
        }

        return IsDriveQualified(path) || IsUnc(path);
    }

    /// <summary>Whether the path begins with a drive letter, as in <c>C:\folder</c>.</summary>
    private static bool IsDriveQualified(string path) =>
        path.Length >= 3
        && char.IsAsciiLetter(path[0])
        && path[1] == ':'
        && IsSeparator(path[2]);

    /// <summary>Whether the path is a UNC share, as in <c>\\server\share</c>.</summary>
    private static bool IsUnc(string path) =>
        path.Length > 2
        && IsSeparator(path[0])
        && IsSeparator(path[1])
        && !IsSeparator(path[2]);

    private static bool IsSeparator(char c) => c is '\\' or '/';
}
