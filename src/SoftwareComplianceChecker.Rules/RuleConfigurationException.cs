namespace SoftwareComplianceChecker.Rules;

/// <summary>
/// Thrown when the rules file is missing, malformed, or semantically invalid.
/// </summary>
/// <remarks>
/// This is deliberately fatal. A compliance tool that silently continues with a broken
/// policy file reports PASS for everything, which is worse than reporting nothing at all.
/// </remarks>
public sealed class RuleConfigurationException : Exception
{
    /// <summary>Creates an exception describing one or more configuration problems.</summary>
    /// <param name="message">Summary of the failure.</param>
    /// <param name="errors">Individual problems found.</param>
    public RuleConfigurationException(string message, IReadOnlyList<string>? errors = null)
        : base(Compose(message, errors))
    {
        this.Errors = errors ?? [];
    }

    /// <summary>Creates an exception wrapping an underlying failure.</summary>
    /// <param name="message">Summary of the failure.</param>
    /// <param name="innerException">The underlying cause.</param>
    public RuleConfigurationException(string message, Exception innerException)
        : base(message, innerException)
    {
        this.Errors = [];
    }

    /// <summary>The individual problems found, when validation produced more than one.</summary>
    public IReadOnlyList<string> Errors { get; }

    private static string Compose(string message, IReadOnlyList<string>? errors)
    {
        if (errors is null || errors.Count == 0)
        {
            return message;
        }

        return message + Environment.NewLine +
               string.Join(Environment.NewLine, errors.Select(e => "  - " + e));
    }
}
