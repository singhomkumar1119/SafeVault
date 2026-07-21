using System.Net;
using System.Net.Http.Json;
using SafeVault.Web.Models;
using Xunit;

namespace SafeVault.Tests;

public class AuthorizationTests : IClassFixture<SafeVaultFactory>
{
    private readonly SafeVaultFactory _factory;

    public AuthorizationTests(SafeVaultFactory factory) => _factory = factory;

    [Fact]
    public async Task VaultEndpoint_WithoutLogin_Returns401()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/vault/notes");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AdminEndpoint_AsRegularUser_Returns403()
    {
        var client = _factory.CreateClient();
        await client.PostAsJsonAsync("/api/auth/register",
            new RegisterRequest("regularjoe", "joe@example.com", "Password123"));
        await client.PostAsJsonAsync("/api/auth/login", new LoginRequest("regularjoe", "Password123"));

        var response = await client.GetAsync("/api/admin/users");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AdminEndpoint_AsAdmin_Returns200()
    {
        var client = _factory.CreateClient();

        // Seeded by DbInitializer for every fresh DB.
        var login = await client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("admin", "ChangeMe123!"));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        var response = await client.GetAsync("/api/admin/users");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task VaultEndpoint_AsLoggedInUser_Returns200()
    {
        var client = _factory.CreateClient();
        await client.PostAsJsonAsync("/api/auth/register",
            new RegisterRequest("vaultuser", "vault@example.com", "Password123"));
        await client.PostAsJsonAsync("/api/auth/login", new LoginRequest("vaultuser", "Password123"));

        var response = await client.GetAsync("/api/vault/notes");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Login_WithWrongPassword_Returns401()
    {
        var client = _factory.CreateClient();
        await client.PostAsJsonAsync("/api/auth/register",
            new RegisterRequest("wrongpassuser", "wp@example.com", "Password123"));

        var response = await client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("wrongpassuser", "TotallyWrong1"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
