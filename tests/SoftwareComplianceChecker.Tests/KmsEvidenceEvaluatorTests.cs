using Shouldly;
using SoftwareComplianceChecker.Core.Models;
using SoftwareComplianceChecker.Scanning;
using Xunit;

namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// The licensing verdict is the part of the product most easily got wrong, because a
/// KMS-activated machine reports itself as activated. These tests pin the corroborating
/// signals that distinguish it.
/// </summary>
public sealed class KmsEvidenceEvaluatorTests
{
    private const int Licensed = 1;

    private static LicenseEvidence Retail() => new()
    {
        LicenseStatusCode = Licensed,
        ProductKeyChannel = "Retail",
        LicenseDescription = "Windows(R) Operating System, RETAIL channel",
        PartialProductKey = "ABCDE",
    };

    [Fact]
    public void Retail_with_no_kms_signals_passes()
    {
        var result = KmsEvidenceEvaluator.Evaluate(Retail());

        result.Status.ShouldBe(ComplianceStatus.Pass);
        result.ActivationType.ShouldBe(ActivationType.Retail);
        result.KmsEvidence.ShouldBeEmpty();
    }

    [Fact]
    public void An_activated_machine_using_a_volume_client_key_still_fails()
    {
        // The whole point: LicenseStatus says "Licensed", yet this machine is KMS activated.
        var evidence = Retail() with
        {
            ProductKeyChannel = "Volume:GVLK",
            LicenseDescription = "Windows(R) Operating System, VOLUME_KMSCLIENT channel",
        };

        var result = KmsEvidenceEvaluator.Evaluate(evidence);

        result.Status.ShouldBe(ComplianceStatus.Fail);
        result.Reason.ShouldBe(KmsEvidenceEvaluator.KmsReason);
        result.ActivationType.ShouldBe(ActivationType.Kms);
        result.KmsEvidence.Count.ShouldBeGreaterThanOrEqualTo(1);
    }

    [Fact]
    public void A_configured_kms_host_is_evidence()
    {
        var result = KmsEvidenceEvaluator.Evaluate(Retail() with { KmsServerName = "kms.local", KmsServerPort = 1688 });

        result.Status.ShouldBe(ComplianceStatus.Fail);
        result.KmsEvidence.ShouldContain(e => e.Contains("kms.local", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(180 * 24 * 60, true)]   // the canonical KMS renewal period
    [InlineData(160 * 24 * 60, true)]
    [InlineData(30 * 24 * 60, false)]   // an ordinary grace period, not KMS
    [InlineData(365 * 24 * 60, false)]
    public void An_expiry_near_the_kms_renewal_window_is_evidence(int minutes, bool expectFail)
    {
        var result = KmsEvidenceEvaluator.Evaluate(Retail() with { GracePeriodMinutes = minutes });

        result.Status.ShouldBe(expectFail ? ComplianceStatus.Fail : ComplianceStatus.Pass);
    }

    [Fact]
    public void An_activation_tool_trace_is_evidence()
    {
        var evidence = Retail() with
        {
            ActivationToolTraces = ["A Windows service named 'AutoKMS' matches the known activation tool 'AutoKMS'."],
        };

        var result = KmsEvidenceEvaluator.Evaluate(evidence);

        result.Status.ShouldBe(ComplianceStatus.Fail);
        result.KmsEvidence.ShouldContain(e => e.Contains("AutoKMS", StringComparison.Ordinal));
    }

    [Fact]
    public void An_unactivated_machine_fails_even_without_kms_signals()
    {
        var result = KmsEvidenceEvaluator.Evaluate(Retail() with { LicenseStatusCode = 0 });

        result.Status.ShouldBe(ComplianceStatus.Fail);
        result.Reason.ShouldBe(KmsEvidenceEvaluator.NotActivatedReason);
    }

    [Theory]
    [InlineData("Retail", ActivationType.Retail)]
    [InlineData("OEM:DM", ActivationType.OemDm)]
    [InlineData("OEM:NONSLP", ActivationType.OemCoa)]
    [InlineData("Volume:MAK", ActivationType.Mak)]
    [InlineData("Volume:GVLK", ActivationType.Kms)]
    public void Activation_channel_maps_to_activation_type(string channel, ActivationType expected)
    {
        var result = KmsEvidenceEvaluator.Evaluate(Retail() with
        {
            ProductKeyChannel = channel,
            LicenseDescription = null,
        });

        result.ActivationType.ShouldBe(expected);
    }

    [Fact]
    public void An_oem_firmware_key_implies_oem_when_the_channel_is_unknown()
    {
        var result = KmsEvidenceEvaluator.Evaluate(new LicenseEvidence
        {
            LicenseStatusCode = Licensed,
            OemBiosKeyPresent = true,
        });

        result.ActivationType.ShouldBe(ActivationType.Oem);
        result.Status.ShouldBe(ComplianceStatus.Pass);
    }

    [Fact]
    public void Evidence_is_preserved_on_the_result_for_auditing()
    {
        var evidence = Retail() with { KmsServerName = "kms.local" };

        var result = KmsEvidenceEvaluator.Evaluate(evidence);

        // A FAIL must be explainable from the report alone.
        result.Evidence.ShouldBeSameAs(evidence);
        result.HasKmsEvidence.ShouldBeTrue();
    }
}
