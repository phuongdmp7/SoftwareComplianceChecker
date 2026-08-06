using SoftwareComplianceChecker.Core.Abstractions;

namespace SoftwareComplianceChecker.Scanning.Platform;

/// <summary>
/// Reads the real file system.
/// </summary>
public sealed class PhysicalFileSystem : IFileSystem
{
    /// <inheritdoc />
    public bool DirectoryExists(string path)
    {
        try
        {
            return Directory.Exists(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public bool FileExists(string path)
    {
        try
        {
            return File.Exists(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public string ExpandPath(string path) => Environment.ExpandEnvironmentVariables(path);

    /// <inheritdoc />
    /// <remarks>
    /// Breadth-first with an explicit depth bound. Directories that cannot be read are
    /// skipped rather than aborting the walk, so one protected folder does not cost the
    /// whole scan.
    /// </remarks>
    public IEnumerable<string> EnumerateFiles(
        string path,
        int maxDepth,
        string searchPattern,
        CancellationToken cancellationToken = default)
    {
        var queue = new Queue<(string Path, int Depth)>();
        queue.Enqueue((path, 0));

        while (queue.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var (current, depth) = queue.Dequeue();

            foreach (var file in SafeGetFiles(current, searchPattern))
            {
                yield return file;
            }

            if (depth >= maxDepth)
            {
                continue;
            }

            foreach (var directory in SafeGetDirectories(current))
            {
                queue.Enqueue((directory, depth + 1));
            }
        }
    }

    private static string[] SafeGetFiles(string path, string searchPattern)
    {
        try
        {
            return Directory.GetFiles(path, searchPattern, SearchOption.TopDirectoryOnly);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static string[] SafeGetDirectories(string path)
    {
        try
        {
            var directories = Directory.GetDirectories(path);

            // Reparse points can loop back on themselves; following them risks an unbounded walk.
            return directories
                .Where(d => !new DirectoryInfo(d).Attributes.HasFlag(FileAttributes.ReparsePoint))
                .ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
