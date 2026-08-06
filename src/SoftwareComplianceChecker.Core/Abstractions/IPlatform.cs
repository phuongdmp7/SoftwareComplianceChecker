namespace SoftwareComplianceChecker.Core.Abstractions;

/// <summary>Registry root to read from.</summary>
public enum RegistryRoot
{
    /// <summary>HKEY_LOCAL_MACHINE.</summary>
    LocalMachine = 0,

    /// <summary>HKEY_CURRENT_USER.</summary>
    CurrentUser = 1,
}

/// <summary>Registry view to read through on 64-bit Windows.</summary>
public enum RegistryBitness
{
    /// <summary>The 64-bit view.</summary>
    Bit64 = 0,

    /// <summary>The 32-bit (WOW6432Node) view.</summary>
    Bit32 = 1,
}

/// <summary>A registry key and its values.</summary>
/// <param name="KeyName">Name of the key, without its parent path.</param>
/// <param name="Values">Value names mapped to their string representation.</param>
public sealed record RegistryKeyData(string KeyName, IReadOnlyDictionary<string, string?> Values);

/// <summary>
/// Reads the Windows registry.
/// </summary>
/// <remarks>
/// Abstracted so that scanner logic is testable on any operating system. The Windows
/// implementation is the only place registry APIs are touched.
/// </remarks>
public interface IRegistryReader
{
    /// <summary>Reads every immediate subkey of a path, with that subkey's values.</summary>
    /// <param name="root">Registry root.</param>
    /// <param name="path">Path beneath the root.</param>
    /// <param name="bitness">Registry view.</param>
    /// <returns>The subkeys, or an empty sequence if the path does not exist.</returns>
    IReadOnlyList<RegistryKeyData> EnumerateSubKeys(RegistryRoot root, string path, RegistryBitness bitness);

    /// <summary>Reads a single value as a string.</summary>
    /// <param name="root">Registry root.</param>
    /// <param name="path">Path beneath the root.</param>
    /// <param name="valueName">Value to read.</param>
    /// <param name="bitness">Registry view.</param>
    /// <returns>The value, or <see langword="null"/> if absent.</returns>
    string? ReadValue(RegistryRoot root, string path, string valueName, RegistryBitness bitness);

    /// <summary>Lists the names of immediate subkeys without reading their values.</summary>
    /// <param name="root">Registry root.</param>
    /// <param name="path">Path beneath the root.</param>
    /// <param name="bitness">Registry view.</param>
    IReadOnlyList<string> GetSubKeyNames(RegistryRoot root, string path, RegistryBitness bitness);
}

/// <summary>
/// Runs WMI queries.
/// </summary>
public interface IWmiQuery
{
    /// <summary>Executes a WQL query and returns each result row as a property bag.</summary>
    /// <param name="scope">WMI scope, for example <c>root\CIMV2</c>.</param>
    /// <param name="query">WQL query text.</param>
    /// <returns>The result rows, or an empty list if the query could not be run.</returns>
    IReadOnlyList<IReadOnlyDictionary<string, object?>> Query(string scope, string query);
}

/// <summary>
/// Reads the file system.
/// </summary>
public interface IFileSystem
{
    /// <summary>Whether a directory exists and is readable.</summary>
    /// <param name="path">Directory path.</param>
    bool DirectoryExists(string path);

    /// <summary>Whether a file exists.</summary>
    /// <param name="path">File path.</param>
    bool FileExists(string path);

    /// <summary>
    /// Enumerates files beneath a directory up to a bounded depth.
    /// </summary>
    /// <param name="path">Directory to search.</param>
    /// <param name="maxDepth">Maximum directory levels to descend. A depth of 0 searches only <paramref name="path"/>.</param>
    /// <param name="searchPattern">File name pattern, for example <c>*.exe</c>.</param>
    /// <param name="cancellationToken">Cancels enumeration.</param>
    /// <returns>Full paths of matching files. Inaccessible directories are skipped rather than throwing.</returns>
    IEnumerable<string> EnumerateFiles(
        string path,
        int maxDepth,
        string searchPattern,
        CancellationToken cancellationToken = default);

    /// <summary>Expands environment variables such as <c>%USERPROFILE%</c> in a path.</summary>
    /// <param name="path">Path possibly containing environment variables.</param>
    string ExpandPath(string path);
}

/// <summary>
/// Describes the machine the scan is running on.
/// </summary>
public interface ISystemInfoProvider
{
    /// <summary>Machine name.</summary>
    string ComputerName { get; }

    /// <summary>Current user, including domain when applicable.</summary>
    string UserName { get; }

    /// <summary>Operating system description.</summary>
    string OperatingSystem { get; }

    /// <summary>Whether the process is running with administrative rights.</summary>
    bool IsElevated { get; }
}
