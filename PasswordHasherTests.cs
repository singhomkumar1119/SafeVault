using SafeVault.Web.Services;
using Xunit;

namespace SafeVault.Tests;

public class PasswordHasherTests
{
    [Fact]
    public void Hash_ProducesDifferentSaltsForSamePassword()
    {
        var (hash1, salt1) = PasswordHasher.Hash("Password123");
        var (hash2, salt2) = PasswordHasher.Hash("Password123");

        Assert.NotEqual(salt1, salt2);
        Assert.NotEqual(hash1, hash2); // different salt -> different hash even for the same password
    }

    [Fact]
    public void Verify_WithCorrectPassword_ReturnsTrue()
    {
        var (hash, salt) = PasswordHasher.Hash("Correct-Password1");
        Assert.True(PasswordHasher.Verify("Correct-Password1", hash, salt));
    }

    [Fact]
    public void Verify_WithWrongPassword_ReturnsFalse()
    {
        var (hash, salt) = PasswordHasher.Hash("Correct-Password1");
        Assert.False(PasswordHasher.Verify("Wrong-Password1", hash, salt));
    }

    [Fact]
    public void Hash_NeverStoresPlaintext()
    {
        var (hash, _) = PasswordHasher.Hash("Correct-Password1");
        Assert.DoesNotContain("Correct-Password1", hash);
    }
}
