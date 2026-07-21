using SafeVault.Web.Services;
using Xunit;

namespace SafeVault.Tests;

public class InputValidatorTests
{
    [Theory]
    [InlineData("john_doe123", true)]
    [InlineData("ab", false)]                    // too short
    [InlineData("this_username_is_way_too_long_to_be_valid_ok", false)] // too long
    [InlineData("john doe", false)]               // space not allowed
    [InlineData("john'--", false)]                // SQL metacharacters not allowed
    [InlineData("<script>", false)]                // XSS-style chars not allowed
    [InlineData("", false)]
    public void ValidateUsername_EnforcesAllowlist(string input, bool expectedValid)
    {
        var result = InputValidator.ValidateUsername(input);
        Assert.Equal(expectedValid, result.IsValid);
    }

    [Theory]
    [InlineData("user@example.com", true)]
    [InlineData("not-an-email", false)]
    [InlineData("", false)]
    public void ValidateEmail_BasicShapeCheck(string input, bool expectedValid)
    {
        var result = InputValidator.ValidateEmail(input);
        Assert.Equal(expectedValid, result.IsValid);
    }

    [Theory]
    [InlineData("Password123", true)]
    [InlineData("short1A", false)]        // < 8 chars
    [InlineData("alllowercase1", false)]  // no uppercase
    [InlineData("ALLUPPERCASE1", false)]  // no lowercase
    [InlineData("NoDigitsHere", false)]   // no digit
    public void ValidatePassword_EnforcesComplexity(string input, bool expectedValid)
    {
        var result = InputValidator.ValidatePassword(input);
        Assert.Equal(expectedValid, result.IsValid);
    }

    [Fact]
    public void EncodeForOutput_EscapesHtmlSpecialCharacters()
    {
        string encoded = InputValidator.EncodeForOutput("<script>alert('x')</script>");

        Assert.DoesNotContain("<script>", encoded);
        Assert.Contains("&lt;script&gt;", encoded);
    }

    [Fact]
    public void EncodeForOutput_NullOrEmpty_ReturnsEmptyString()
    {
        Assert.Equal(string.Empty, InputValidator.EncodeForOutput(null));
        Assert.Equal(string.Empty, InputValidator.EncodeForOutput(""));
    }
}
