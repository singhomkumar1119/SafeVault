using System.Net;
using System.Net.Http.Json;
using SafeVault.Web.Models;
using Xunit;

namespace SafeVault.Tests;

public class SqlInjectionTests : IClassFixture<SafeVaultFactory>
{
    private readonly SafeVaultFactory _factory;

    public SqlInjectionTests(SafeVaultFactory factory) => _factory = factory;

    [Theory]
    [InlineData("' OR '1'='1")]
    [InlineData("admin'--")]
    [InlineData("'; DROP TABLE Users; --")]
    [InlineData("' UNION SELECT * FROM Users --")]
    public async Task Login_WithSqlInjectionPayloadAsUsername_IsRejected(string payload)
    {
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest(payload, "whatever-password"));

        // Should be rejected outright by input validation (username allowlist),
        // and even if it somehow reached the query, parameterization means it
        // cannot log the attacker in or damage the database.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Register_WithSqlInjectionPayloadAsUsername_IsRejectedByValidation()
    {
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/auth/register",
            new RegisterRequest("'; DROP TABLE Users; --", "attacker@example.com", "Password123"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task DatabaseSurvives_InjectionAttempts_LegitimateUsersStillWork()
    {
        var client = _factory.CreateClient();

        // Fire a batch of injection attempts at login first.
        foreach (var payload in new[] { "' OR '1'='1", "'; DROP TABLE Users; --", "x' OR 1=1 --" })
        {
            await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(payload, "irrelevant"));
        }

        // The Users table must still exist and work normally afterwards —
        // proves the injection payloads never reached the SQL engine as code.
        var register = await client.PostAsJsonAsync("/api/auth/register",
            new RegisterRequest("legituser1", "legit1@example.com", "Password123"));
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        var login = await client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("legituser1", "Password123"));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }
}
