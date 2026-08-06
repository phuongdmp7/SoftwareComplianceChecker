using System.Runtime.InteropServices;
using System.Security.Principal;
using SoftwareComplianceChecker.Core.Abstractions;

namespace SoftwareComplianceChecker.Scanning.Platform;

/// <summary>
/// Describes the machine the scan is running on.
/// </summary>
public sealed class SystemInfoProvider : ISystemInfoProvider
{
    /// <inheritdoc />
    public string ComputerName => Environment.MachineName;

    /// <inheritdoc />
    public string UserName =>
        string.IsNullOrWhiteSpace(Environment.UserDomainName)
            ? Environment.UserName
            : $"{Environment.UserDomainName}\\{Environment.UserName}";

    /// <inheritdoc />
    public string OperatingSystem => RuntimeInformation.OSDescription;

    /// <inheritdoc />
    /// <remarks>
    /// Elevation matters because some evidence, notably scheduled tasks, is unreadable
    /// without it. A scan that quietly missed that evidence could report a false PASS.
    /// </remarks>
    public bool IsElevated
    {
        get
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or PlatformNotSupportedException)
            {
                return false;
            }
        }
    }
}
