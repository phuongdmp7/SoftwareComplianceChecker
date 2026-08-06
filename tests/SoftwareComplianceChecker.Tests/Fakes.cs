using SoftwareComplianceChecker.Core.Abstractions;

namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// In-memory registry, so scanner logic can be exercised without Windows.
/// </summary>
internal sealed class FakeRegistryReader : IRegistryReader
{
    private readonly Dictionary<string, List<RegistryKeyData>> subKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string?> values = new(StringComparer.OrdinalIgnoreCase);

    public void AddSubKey(RegistryRoot root, string path, RegistryBitness bitness, RegistryKeyData key)
    {
        var mapKey = Key(root, path, bitness);

        if (!this.subKeys.TryGetValue(mapKey, out var list))
        {
            list = [];
            this.subKeys[mapKey] = list;
        }

        list.Add(key);
    }

    public void SetValue(RegistryRoot root, string path, string valueName, RegistryBitness bitness, string? value) =>
        this.values[Key(root, path, bitness) + "::" + valueName] = value;

    public IReadOnlyList<RegistryKeyData> EnumerateSubKeys(RegistryRoot root, string path, RegistryBitness bitness) =>
        this.subKeys.TryGetValue(Key(root, path, bitness), out var list) ? list : [];

    public string? ReadValue(RegistryRoot root, string path, string valueName, RegistryBitness bitness) =>
        this.values.TryGetValue(Key(root, path, bitness) + "::" + valueName, out var value) ? value : null;

    public IReadOnlyList<string> GetSubKeyNames(RegistryRoot root, string path, RegistryBitness bitness) =>
        this.EnumerateSubKeys(root, path, bitness).Select(k => k.KeyName).ToArray();

    private static string Key(RegistryRoot root, string path, RegistryBitness bitness) =>
        $"{root}|{path}|{bitness}";
}

/// <summary>
/// In-memory file system that records the depth each path sits at.
/// </summary>
internal sealed class FakeFileSystem : IFileSystem
{
    private readonly HashSet<string> directories = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Files keyed by the directory that contains them.</summary>
    private readonly Dictionary<string, List<string>> filesByDirectory = new(StringComparer.OrdinalIgnoreCase);

    public void AddDirectory(string path) => this.directories.Add(Normalize(path));

    public void AddFile(string directory, string fileName)
    {
        this.AddDirectory(directory);

        var key = Normalize(directory);

        if (!this.filesByDirectory.TryGetValue(key, out var list))
        {
            list = [];
            this.filesByDirectory[key] = list;
        }

        list.Add(fileName);
    }

    public bool DirectoryExists(string path) => this.directories.Contains(Normalize(path));

    public bool FileExists(string path) =>
        this.filesByDirectory.TryGetValue(Normalize(GetDirectory(path)), out var list)
        && list.Contains(GetFileName(path), StringComparer.OrdinalIgnoreCase);

    public string ExpandPath(string path) => path;

    public IEnumerable<string> EnumerateFiles(
        string path,
        int maxDepth,
        string searchPattern,
        CancellationToken cancellationToken = default)
    {
        var root = Normalize(path);

        foreach (var (directory, files) in this.filesByDirectory)
        {
            if (!directory.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (DepthBelow(root, directory) > maxDepth)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (Matches(file, searchPattern))
                {
                    yield return directory + Path.DirectorySeparatorChar + file;
                }
            }
        }
    }

    private static bool Matches(string fileName, string searchPattern)
    {
        if (searchPattern == "*")
        {
            return true;
        }

        var extension = searchPattern.TrimStart('*');
        return fileName.EndsWith(extension, StringComparison.OrdinalIgnoreCase);
    }

    private static int DepthBelow(string root, string directory)
    {
        if (directory.Length <= root.Length)
        {
            return 0;
        }

        return directory[root.Length..].Count(c => c == Path.DirectorySeparatorChar);
    }

    /// <summary>
    /// Rewrites Windows-style separators to the host's separator.
    /// </summary>
    /// <remarks>
    /// The tests are written with Windows paths because that is what the product scans, but
    /// they run on Linux too, where <see cref="Path.GetFileName(string)"/> does not treat a
    /// backslash as a separator. Normalising here keeps the tests about scanner behaviour
    /// rather than about path syntax.
    /// </remarks>
    private static string Normalize(string path) =>
        path.Replace('\\', Path.DirectorySeparatorChar)
            .Replace('/', Path.DirectorySeparatorChar)
            .TrimEnd(Path.DirectorySeparatorChar);

    private static string GetDirectory(string path)
    {
        var normalized = Normalize(path);
        var index = normalized.LastIndexOf(Path.DirectorySeparatorChar);
        return index < 0 ? normalized : normalized[..index];
    }

    private static string GetFileName(string path)
    {
        var normalized = Normalize(path);
        var index = normalized.LastIndexOf(Path.DirectorySeparatorChar);
        return index < 0 ? normalized : normalized[(index + 1)..];
    }
}

/// <summary>
/// WMI stub returning canned rows.
/// </summary>
internal sealed class FakeWmiQuery : IWmiQuery
{
    private readonly List<(string Fragment, IReadOnlyDictionary<string, object?> Row)> rows = [];

    public void AddRow(string queryFragment, IReadOnlyDictionary<string, object?> row) =>
        this.rows.Add((queryFragment, row));

    public IReadOnlyList<IReadOnlyDictionary<string, object?>> Query(string scope, string query) =>
        this.rows.Where(r => query.Contains(r.Fragment, StringComparison.OrdinalIgnoreCase))
                 .Select(r => r.Row)
                 .ToArray();
}

/// <summary>
/// Fixed machine description.
/// </summary>
internal sealed class FakeSystemInfoProvider : ISystemInfoProvider
{
    public string ComputerName { get; set; } = "TEST-PC";

    public string UserName { get; set; } = "TEST\\user";

    public string OperatingSystem { get; set; } = "Microsoft Windows 11 Pro";

    public bool IsElevated { get; set; } = true;
}
