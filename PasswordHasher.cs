using System.Security.Cryptography;

namespace SafeVault.Web.Services;

/// <summary>
/// Hashes and verifies passwords with PBKDF2-HMAC-SHA256, a salt per user,
/// and a high iteration count. Plaintext passwords are never stored or logged.
/// </summary>
public static class PasswordHasher
{
    private const int SaltSize = 16;      // 128-bit salt
    private const int KeySize = 32;       // 256-bit derived key
    private const int Iterations = 210_000; // OWASP-recommended minimum (2023+) for PBKDF2-SHA256

    public static (string Hash, string Salt) Hash(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, KeySize);
        return (Convert.ToBase64String(key), Convert.ToBase64String(salt));
    }

    public static bool Verify(string password, string storedHash, string storedSalt)
    {
        byte[] salt = Convert.FromBase64String(storedSalt);
        byte[] expected = Convert.FromBase64String(storedHash);
        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, KeySize);

        // Constant-time comparison to avoid timing attacks.
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}
