using System.Text.Json;
using SoftwareComplianceChecker.Core.Configuration;

namespace SoftwareComplianceChecker.Scanning;

/// <summary>
/// Loads the portable scan configuration from portableFolders.json.
/// </summary>
public static class PortableFolderOptionsLoader
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>
    /// Reads the configuration, falling back to a documented default when the file is absent.
    /// </summary>
    /// <param name="path">Path to portableFolders.json.</param>
    /// <returns>The loaded options, and a warning when the file could not be used.</returns>
    /// <remarks>
    /// Unlike rules.json, a missing folder list is recoverable: the scan still runs against
    /// the default folders. A malformed one is reported rather than silently ignored, so a
    /// typo cannot quietly shrink the search surface.
    /// </remarks>
    public static (PortableFolderOptions Options, string? Warning) Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
        {
            return (CreateDefault(), $"Portable folder configuration was not found at '{path}'. Default folders were used.");
        }

        try
        {
            var json = File.ReadAllText(path);
            var options = JsonSerializer.Deserialize<PortableFolderOptions>(json, SerializerOptions);

            if (options is null || options.Folders.Count == 0)
            {
                return (CreateDefault(), $"Portable folder configuration at '{path}' listed no folders. Default folders were used.");
            }

            if (options.MaxDepth < 0)
            {
                return (CreateDefault(), $"Portable folder configuration at '{path}' has a negative depth. Default folders were used.");
            }

            return (options, null);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return (CreateDefault(), $"Portable folder configuration at '{path}' could not be read: {ex.Message}. Default folders were used.");
        }
    }

    /// <summary>The folders searched when no configuration file is available.</summary>
    public static PortableFolderOptions CreateDefault() => new()
    {
        MaxDepth = 3,
        Folders =
        [
            new PortableFolder { Path = @"%USERPROFILE%\Desktop" },
            new PortableFolder { Path = @"%USERPROFILE%\Downloads" },
            new PortableFolder { Path = @"%USERPROFILE%\Documents" },
            new PortableFolder { Path = @"C:\Tools" },
            new PortableFolder { Path = @"D:\Tools" },
            new PortableFolder { Path = @"D:\Apps" },
            new PortableFolder { Path = @"E:\Apps" },
        ],
    };
}
