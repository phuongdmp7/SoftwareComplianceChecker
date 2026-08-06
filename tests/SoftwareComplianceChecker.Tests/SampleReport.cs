using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// A fixed report used by export tests and to generate the committed sample reports, so the
/// samples are real exporter output rather than hand-written approximations.
/// </summary>
internal static class SampleReport
{
    public static ComplianceReport Create() => new()
    {
        ComputerName = "WORKSTATION-01",
        UserName = "CONTOSO\\jsmith",
        OperatingSystem = "Microsoft Windows 11 Pro (10.0.26100)",
        ScanTime = new DateTimeOffset(2026, 8, 6, 9, 30, 0, TimeSpan.Zero),
        Duration = TimeSpan.FromSeconds(6.42),
        License = CreateLicense(),
        InstalledSoftware = CreateInstalled(),
        PortableSoftware = CreatePortable(),
        Warnings =
        [
            "The scan ran without administrative rights. Some evidence, such as scheduled tasks, may not have been readable.",
        ],
    };

    private static WindowsLicenseInfo CreateLicense() => new()
    {
        Evidence = new LicenseEvidence
        {
            Edition = "Professional",
            ProductName = "Windows 11 Pro",
            Version = "24H2",
            BuildNumber = "26100.1742",
            LicenseStatus = "Licensed",
            LicenseStatusCode = 1,
            ProductKeyChannel = "Volume:GVLK",
            LicenseDescription = "Windows(R) Operating System, VOLUME_KMSCLIENT channel",
            PartialProductKey = "3V66T",
            OemBiosKeyPresent = false,
            KmsServerName = "kms.contoso.local",
            KmsServerPort = 1688,
            GracePeriodMinutes = 259200,
        },
        ActivationType = ActivationType.Kms,
        KmsEvidence =
        [
            "Product key channel reports 'Volume:GVLK', which is a KMS client channel.",
            "License description reports 'Windows(R) Operating System, VOLUME_KMSCLIENT channel', which identifies a KMS client.",
            "A KMS host is configured: kms.contoso.local:1688.",
            "Activation expires in approximately 180 days, consistent with the 180-day KMS renewal period rather than a permanent license.",
        ],
        Status = ComplianceStatus.Fail,
        Reason = "Windows appears to use KMS activation.",
    };

    private static ScanFinding[] CreateInstalled() =>
    [
        Finding("Adobe Photoshop 2024", "Adobe Inc.", "25.9.1", @"C:\Program Files\Adobe\Adobe Photoshop 2024",
            ComplianceStatus.Fail, "Software prohibited by policy.", "Adobe", "Adobe (all products)"),
        Finding("JetBrains Rider 2025.1", "JetBrains s.r.o.", "2025.1.2", @"C:\Program Files\JetBrains\Rider 2025.1",
            ComplianceStatus.Fail, "Software prohibited by policy.", "JetBrains", "JetBrains (all products)"),
        Finding("Microsoft 365 Apps for enterprise", "Microsoft Corporation", "16.0.18324.20168",
            @"C:\Program Files\Microsoft Office", ComplianceStatus.Fail, "Software prohibited by policy.",
            "Microsoft Office", "Microsoft Office (all editions)"),
        Finding("WinRAR 7.01 (64-bit)", "win.rar GmbH", "7.01", @"C:\Program Files\WinRAR",
            ComplianceStatus.Fail, "Software prohibited by policy.", "Compression", "WinRAR"),
        Finding("Blender", "Blender Foundation", "4.2.1", @"C:\Program Files\Blender Foundation\Blender 4.2",
            ComplianceStatus.Pass, "No matching compliance rule."),
        Finding("Git", "The Git Development Community", "2.46.0", @"C:\Program Files\Git",
            ComplianceStatus.Pass, "Permitted by policy.", "Permitted",
            "Explicitly permitted development and creative tools"),
        Finding("Unity Hub", "Unity Technologies ApS", "3.9.1", @"C:\Program Files\Unity Hub",
            ComplianceStatus.Pass, "Permitted by policy.", "Permitted",
            "Explicitly permitted development and creative tools"),
        Finding("Visual Studio Code", "Microsoft Corporation", "1.93.1",
            @"C:\Users\jsmith\AppData\Local\Programs\Microsoft VS Code", ComplianceStatus.Pass,
            "Permitted by policy.", "Permitted", "Explicitly permitted development and creative tools"),
    ];

    private static ScanFinding[] CreatePortable() =>
    [
        new()
        {
            Name = "Toolbag",
            Version = null,
            Location = @"C:\Users\jsmith\Downloads\Marmoset\Toolbag.exe",
            Status = ComplianceStatus.Fail,
            Reason = "Software prohibited by policy.",
            Category = "Marmoset",
            MatchedRule = "Marmoset",
            Section = FindingSection.PortableSoftware,
        },
    ];

    private static ScanFinding Finding(
        string name,
        string publisher,
        string version,
        string location,
        ComplianceStatus status,
        string reason,
        string? category = null,
        string? matchedRule = null) => new()
        {
            Name = name,
            Publisher = publisher,
            Version = version,
            Location = location,
            Status = status,
            Reason = reason,
            Category = category,
            MatchedRule = matchedRule,
            Section = FindingSection.InstalledSoftware,
        };
}
