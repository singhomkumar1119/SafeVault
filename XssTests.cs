using System.Net;
using System.Net.Http.Json;
using SafeVault.Web.Models;
using Xunit;

namespace SafeVault.Tests;

public class XssTests : IClassFixture<SafeVaultFactory>
{
    private readonly SafeVaultFactory _factory;

    public XssTests(SafeVaultFactory factory) => _factory = factory;

    private async Task<HttpClient> LoggedInClientAsync(string username)
    {
        var client = _factory.CreateClient();
        await client.PostAsJsonAsync("/api/auth/register",
            new RegisterRequest(username, $"{username}@example.com", "Password123"));
        await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(username, "Password123"));
        return client;
    }

    [Theory]
    [InlineData("<script>alert('xss')</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("<svg/onload=alert(1)>")]
    public async Task NoteText_ContainingScriptPayload_IsHtmlEncodedOnReturn(string payload)
    {
        var client = await LoggedInClientAsync($"xssuser{Math.Abs(payload.GetHashCode())}");

        var create = await client.PostAsJsonAsync("/api/vault/notes", new CreateNoteRequest(payload));
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);

        var body = await create.Content.ReadAsStringAsync();

        // The raw, executable payload must never appear verbatim in the response.
        Assert.DoesNotContain("<script>", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<svg", body, StringComparison.OrdinalIgnoreCase);

        // It should instead appear HTML-encoded (e.g. "&lt;script&gt;").
        Assert.Contains("&lt;", body);
    }

    [Fact]
    public async Task GetNotes_ReturnsEncodedText_ForPreviouslyStoredPayload()
    {
        var client = await LoggedInClientAsync("xsslistuser");
        await client.PostAsJsonAsync("/api/vault/notes",
            new CreateNoteRequest("<script>document.location='https://evil.example'</script>"));

        var list = await client.GetAsync("/api/vault/notes");
        var body = await list.Content.ReadAsStringAsync();

        Assert.DoesNotContain("<script>", body, StringComparison.OrdinalIgnoreCase);
    }
}
