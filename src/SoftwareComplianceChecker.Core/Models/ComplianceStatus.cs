namespace SoftwareComplianceChecker.Core.Models;

/// <summary>
/// The result of a single compliance check.
/// </summary>
/// <remarks>
/// The policy is deliberately binary. There is no warning or indeterminate state,
/// and none may be added: a compliance verdict that cannot be acted on is not a verdict.
/// </remarks>
public enum ComplianceStatus
{
    /// <summary>The item complies with the policy.</summary>
    Pass = 0,

    /// <summary>The item violates the policy.</summary>
    Fail = 1,
}
