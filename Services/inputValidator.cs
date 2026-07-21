using System.Net;
using System.Text.RegularExpressions;

namespace SafeVault.Web.Services;

/// <summary>
/// Centralized input validation for SafeVault.
///
/// SECURITY NOTE: Validation here is a defense-in-depth *first layer*, not the
/// actual SQL injection defense. The real defense against SQL injection is
/// ALWAYS using parameterized queries (see Data/SqliteUserRepository.cs and
/// Data/SqliteNoteRepository.cs) so that user input is never concatenated into
/// SQL text. Validation exists to reject obviously malformed/malicious input
/// early and to give the user a clear error, and output-encoding (see
/// EncodeForOutput) is what prevents Cross-Site Scripting (XSS).
/// </summary>
public static class InputValidator
{
    private static readonly Regex UsernamePattern = new("^[a-zA-Z0-9_]{3,32}$", RegexOptions.Compiled);
    private static readonly Regex EmailPattern = new(
        @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled);

    public static ValidationResult ValidateUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return ValidationResult.Fail("Username is required.");

        username = username.Trim();

        if (!UsernamePattern.IsMatch(username))
            return ValidationResult.Fail(
                "Username must be 3-32 characters and contain only letters, numbers, and underscores.");

        return ValidationResult.Ok(username);
    }

    public static ValidationResult ValidateEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return ValidationResult.Fail("Email is required.");

        email = email.Trim();

        if (email.Length > 254 || !EmailPattern.IsMatch(email))
            return ValidationResult.Fail("Email address is not valid.");

        return ValidationResult.Ok(email);
    }

    public static ValidationResult ValidatePassword(string? password)
    {
        if (string.IsNullOrEmpty(password))
            return ValidationResult.Fail("Password is required.");

        if (password.Length < 8 || password.Length > 128)
            return ValidationResult.Fail("Password must be between 8 and 128 characters.");

        bool hasUpper = password.Any(char.IsUpper);
        bool hasLower = password.Any(char.IsLower);
        bool hasDigit = password.Any(char.IsDigit);

        if (!hasUpper || !hasLower || !hasDigit)
            return ValidationResult.Fail(
                "Password must include an uppercase letter, a lowercase letter, and a digit.");

        return ValidationResult.Ok(password);
    }

    public static ValidationResult ValidateNoteText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return ValidationResult.Fail("Note text cannot be empty.");

        text = text.Trim();

        if (text.Length > 2000)
            return ValidationResult.Fail("Note text cannot exceed 2000 characters.");

        return ValidationResult.Ok(text);
    }

    /// <summary>
    /// HTML-encodes text before it is ever written into an HTML response.
    /// This is the actual defense against stored/reflected XSS: data is stored
    /// as the user typed it, but it is ALWAYS encoded at the point of output.
    /// </summary>
    public static string EncodeForOutput(string? text)
    {
        return string.IsNullOrEmpty(text) ? string.Empty : WebUtility.HtmlEncode(text);
    }
}

public sealed class ValidationResult
{
    public bool IsValid { get; }
    public string? Value { get; }
    public string? Error { get; }

    private ValidationResult(bool isValid, string? value, string? error)
    {
        IsValid = isValid;
        Value = value;
        Error = error;
    }

    public static ValidationResult Ok(string value) => new(true, value, null);
    public static ValidationResult Fail(string error) => new(false, null, error);
}
