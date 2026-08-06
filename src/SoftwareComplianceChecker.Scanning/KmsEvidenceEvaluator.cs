using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Scanning;

/// <summary>
/// Derives a Windows licensing verdict from collected evidence.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately a pure function over <see cref="LicenseEvidence"/> with no I/O, so the
/// decision logic can be exercised in unit tests on any operating system.
/// </para>
/// <para>
/// The naive check — "does Windows report itself as activated?" — is not sufficient:
/// KMS-activated machines report themselves as fully activated. The verdict therefore rests
/// on corroborating signals rather than the activation flag alone.
/// </para>
/// </remarks>
public static class KmsEvidenceEvaluator
{
    /// <summary>Windows reports a licensed product with status code 1.</summary>
    private const int LicensedStatusCode = 1;

    /// <summary>
    /// KMS activation is valid for 180 days and renews periodically. A remaining period in
    /// this window is characteristic of KMS rather than a permanent Retail or OEM license.
    /// </summary>
    private const int KmsWindowLowerMinutes = 150 * 24 * 60;

    /// <summary>Upper bound of the KMS renewal window, in minutes.</summary>
    private const int KmsWindowUpperMinutes = 210 * 24 * 60;

    /// <summary>Verdict text used when KMS activation is indicated.</summary>
    public const string KmsReason = "Windows appears to use KMS activation.";

    /// <summary>Verdict text used when Windows is not activated at all.</summary>
    public const string NotActivatedReason = "Windows is not activated.";

    /// <summary>Verdict text used when no KMS evidence was found.</summary>
    public const string GenuineReason =
        "Windows appears to be activated through a Retail or OEM channel with no evidence of KMS activation.";

    /// <summary>
    /// Evaluates collected licensing evidence.
    /// </summary>
    /// <param name="evidence">The facts gathered from WMI, the registry and the file system.</param>
    /// <returns>The activation type, the KMS indicators found, and the resulting verdict.</returns>
    public static WindowsLicenseInfo Evaluate(LicenseEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        var kmsEvidence = CollectKmsEvidence(evidence);
        var activationType = DetermineActivationType(evidence, kmsEvidence.Count > 0);

        var (status, reason) = Decide(evidence, kmsEvidence);

        return new WindowsLicenseInfo
        {
            Evidence = evidence,
            ActivationType = activationType,
            KmsEvidence = kmsEvidence,
            Status = status,
            Reason = reason,
        };
    }

    private static (ComplianceStatus Status, string Reason) Decide(
        LicenseEvidence evidence,
        IReadOnlyList<string> kmsEvidence)
    {
        // An unactivated machine fails regardless of channel: the policy requires a
        // legitimately activated Windows, not merely the absence of KMS.
        if (evidence.LicenseStatusCode is not null && evidence.LicenseStatusCode != LicensedStatusCode)
        {
            return (ComplianceStatus.Fail, NotActivatedReason);
        }

        if (kmsEvidence.Count > 0)
        {
            return (ComplianceStatus.Fail, KmsReason);
        }

        return (ComplianceStatus.Pass, GenuineReason);
    }

    private static List<string> CollectKmsEvidence(LicenseEvidence evidence)
    {
        var found = new List<string>();

        // A GVLK is the generic volume key a KMS client uses. Its presence is the single
        // strongest indicator available, short of finding an activation tool.
        if (ContainsAny(evidence.ProductKeyChannel, "GVLK", "KMS"))
        {
            found.Add($"Product key channel reports '{evidence.ProductKeyChannel}', which is a KMS client channel.");
        }

        if (ContainsAny(evidence.LicenseDescription, "KMSCLIENT", "KMS_CLIENT", "VOLUME_KMSCLIENT"))
        {
            found.Add($"License description reports '{evidence.LicenseDescription}', which identifies a KMS client.");
        }

        if (!string.IsNullOrWhiteSpace(evidence.KmsServerName))
        {
            var port = evidence.KmsServerPort is null ? string.Empty : $":{evidence.KmsServerPort}";
            found.Add($"A KMS host is configured: {evidence.KmsServerName}{port}.");
        }

        if (evidence.GracePeriodMinutes is { } minutes
            && minutes is >= KmsWindowLowerMinutes and <= KmsWindowUpperMinutes)
        {
            found.Add(
                $"Activation expires in approximately {minutes / (24 * 60)} days, " +
                "consistent with the 180-day KMS renewal period rather than a permanent license.");
        }

        foreach (var trace in evidence.ActivationToolTraces)
        {
            found.Add(trace);
        }

        return found;
    }

    private static ActivationType DetermineActivationType(LicenseEvidence evidence, bool hasKmsEvidence)
    {
        var channel = evidence.ProductKeyChannel;

        if (ContainsAny(channel, "GVLK") || hasKmsEvidence)
        {
            return ActivationType.Kms;
        }

        if (ContainsAny(channel, "MAK"))
        {
            return ActivationType.Mak;
        }

        if (ContainsAny(channel, "OEM:DM"))
        {
            return ActivationType.OemDm;
        }

        if (ContainsAny(channel, "OEM:COA", "OEM:NONSLP", "COA"))
        {
            return ActivationType.OemCoa;
        }

        if (ContainsAny(channel, "OEM"))
        {
            return ActivationType.Oem;
        }

        if (ContainsAny(channel, "RETAIL"))
        {
            return ActivationType.Retail;
        }

        if (ContainsAny(channel, "VOLUME"))
        {
            return ActivationType.Volume;
        }

        // Firmware-embedded keys identify a machine that shipped with Windows pre-installed.
        return evidence.OemBiosKeyPresent ? ActivationType.Oem : ActivationType.Unknown;
    }

    private static bool ContainsAny(string? value, params string[] needles) =>
        !string.IsNullOrWhiteSpace(value)
        && needles.Any(n => value.Contains(n, StringComparison.OrdinalIgnoreCase));
}
