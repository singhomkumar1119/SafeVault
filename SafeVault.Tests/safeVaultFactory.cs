using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace SafeVault.Tests;

/// <summary>
/// Boots the real SafeVault.Web app in-memory (via WebApplicationFactory) so
/// tests exercise the actual endpoints, actual parameterized queries, and
/// actual authentication/authorization pipeline — not mocks.
/// Each factory instance gets its own throwaway SQLite file so tests don't
/// interfere with each other.
/// </summary>
public class SafeVaultFactory : WebApplicationFactory<Program>
{
    public readonly string DbPath = Path.Combine(Path.GetTempPath(), $"safevault-test-{Guid.NewGuid():N}.db");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:SafeVaultDb"] = $"Data Source={DbPath}"
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (File.Exists(DbPath))
        {
            try { File.Delete(DbPath); } catch { /* best effort cleanup */ }
        }
    }
}
