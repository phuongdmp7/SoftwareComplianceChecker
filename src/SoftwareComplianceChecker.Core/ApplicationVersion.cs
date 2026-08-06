namespace SoftwareComplianceChecker.Core;

/// <summary>
/// Turns a raw assembly version into something worth showing a user.
/// </summary>
/// <remarks>
/// Kept separate from the code that reads the assembly so the formatting, which is the part
/// with rules in it, can be tested without loading one.
/// </remarks>
public static class ApplicationVersion
{
    /// <summary>
    /// Normalises an assembly version for display.
    /// </summary>
    /// <param name="rawVersion">
    /// The value of the informational or file version attribute, for example <c>1.0.3</c> or
    /// <c>1.0.3+a1b2c3d</c>.
    /// </param>
    /// <returns>
    /// A trimmed version such as <c>1.0.3</c>, or <see langword="null"/> when there is nothing
    /// meaningful to show.
    /// </returns>
    /// <remarks>
    /// Build metadata after a <c>+</c> is dropped, since a commit hash is noise in a title
    /// bar. A trailing zero revision is dropped too: the build number Windows records is
    /// four-part, but the version people talk about is three.
    /// </remarks>
    public static string? Normalize(string? rawVersion)
    {
        if (string.IsNullOrWhiteSpace(rawVersion))
        {
            return null;
        }

        var version = rawVersion.Trim();

        var metadataIndex = version.IndexOf('+', StringComparison.Ordinal);
        if (metadataIndex >= 0)
        {
            version = version[..metadataIndex];
        }

        var parts = version.Split('.');
        if (parts.Length == 4 && parts[3] == "0")
        {
            version = string.Join('.', parts[..3]);
        }

        return string.IsNullOrWhiteSpace(version) ? null : version;
    }

    /// <summary>
    /// Builds the window title, appending the version when one is known.
    /// </summary>
    /// <param name="productName">The product name.</param>
    /// <param name="rawVersion">The raw assembly version.</param>
    public static string BuildTitle(string productName, string? rawVersion)
    {
        var version = Normalize(rawVersion);

        return version is null ? productName : $"{productName} ({version})";
    }
}
