namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// Locates files that ship with the repository, so tests can exercise the real configuration
/// rather than a copy that could drift from it.
/// </summary>
internal static class RepositoryFiles
{
    /// <summary>
    /// Finds the shipped compliance policy.
    /// </summary>
    /// <returns>
    /// The path to <c>config/rules.json</c>, or <see langword="null"/> when running outside a
    /// source checkout.
    /// </returns>
    public static string? RulesJson() => Find(Path.Combine("config", "rules.json"));

    private static string? Find(string relativePath)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, relativePath);

            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        return null;
    }
}
