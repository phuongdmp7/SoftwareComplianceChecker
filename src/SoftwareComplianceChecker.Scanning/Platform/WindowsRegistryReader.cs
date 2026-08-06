using System.Security;
using Microsoft.Win32;
using SoftwareComplianceChecker.Core.Abstractions;

namespace SoftwareComplianceChecker.Scanning.Platform;

/// <summary>
/// Reads the real Windows registry.
/// </summary>
/// <remarks>
/// The only type in the solution that touches registry APIs. Missing keys and denied access
/// are reported as absent rather than thrown, because a scan must survive a partially
/// readable machine.
/// </remarks>
public sealed class WindowsRegistryReader : IRegistryReader
{
    /// <inheritdoc />
    public IReadOnlyList<RegistryKeyData> EnumerateSubKeys(RegistryRoot root, string path, RegistryBitness bitness)
    {
        using var baseKey = OpenBaseKey(root, bitness);
        using var parent = TryOpenSubKey(baseKey, path);

        if (parent is null)
        {
            return [];
        }

        var results = new List<RegistryKeyData>();

        foreach (var subKeyName in TryGetSubKeyNames(parent))
        {
            using var subKey = TryOpenSubKey(parent, subKeyName);
            if (subKey is null)
            {
                continue;
            }

            var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

            foreach (var valueName in TryGetValueNames(subKey))
            {
                values[valueName] = ConvertToString(TryGetValue(subKey, valueName));
            }

            results.Add(new RegistryKeyData(subKeyName, values));
        }

        return results;
    }

    /// <inheritdoc />
    public string? ReadValue(RegistryRoot root, string path, string valueName, RegistryBitness bitness)
    {
        using var baseKey = OpenBaseKey(root, bitness);
        using var key = TryOpenSubKey(baseKey, path);

        return key is null ? null : ConvertToString(TryGetValue(key, valueName));
    }

    /// <inheritdoc />
    public IReadOnlyList<string> GetSubKeyNames(RegistryRoot root, string path, RegistryBitness bitness)
    {
        using var baseKey = OpenBaseKey(root, bitness);
        using var key = TryOpenSubKey(baseKey, path);

        return key is null ? [] : TryGetSubKeyNames(key);
    }

    private static RegistryKey OpenBaseKey(RegistryRoot root, RegistryBitness bitness)
    {
        var hive = root switch
        {
            RegistryRoot.LocalMachine => RegistryHive.LocalMachine,
            RegistryRoot.CurrentUser => RegistryHive.CurrentUser,
            _ => throw new ArgumentOutOfRangeException(nameof(root), root, "Unsupported registry root."),
        };

        // Registry32 transparently redirects to WOW6432Node where redirection applies.
        var view = bitness == RegistryBitness.Bit32 ? RegistryView.Registry32 : RegistryView.Registry64;

        return RegistryKey.OpenBaseKey(hive, view);
    }

    private static RegistryKey? TryOpenSubKey(RegistryKey parent, string name)
    {
        try
        {
            return parent.OpenSubKey(name);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    private static IReadOnlyList<string> TryGetSubKeyNames(RegistryKey key)
    {
        try
        {
            return key.GetSubKeyNames();
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return [];
        }
    }

    private static IReadOnlyList<string> TryGetValueNames(RegistryKey key)
    {
        try
        {
            return key.GetValueNames();
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return [];
        }
    }

    private static object? TryGetValue(RegistryKey key, string valueName)
    {
        try
        {
            return key.GetValue(valueName);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    private static string? ConvertToString(object? value) => value switch
    {
        null => null,
        string s => s,
        string[] multi => string.Join("; ", multi),
        byte[] bytes => Convert.ToHexString(bytes),
        _ => value.ToString(),
    };
}
