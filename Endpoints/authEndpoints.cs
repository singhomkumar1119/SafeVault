using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SafeVault.Web.Data;
using SafeVault.Web.Models;
using SafeVault.Web.Services;

namespace SafeVault.Web.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/auth");

        group.MapPost("/register", async (HttpContext ctx, RegisterRequest request, SqliteUserRepository users) =>
        {
            // 1. Validate every field (allowlist validation, defense-in-depth).
            var usernameResult = InputValidator.ValidateUsername(request.Username);
            if (!usernameResult.IsValid) return Results.BadRequest(new { error = usernameResult.Error });

            var emailResult = InputValidator.ValidateEmail(request.Email);
            if (!emailResult.IsValid) return Results.BadRequest(new { error = emailResult.Error });

            var passwordResult = InputValidator.ValidatePassword(request.Password);
            if (!passwordResult.IsValid) return Results.BadRequest(new { error = passwordResult.Error });

            string username = usernameResult.Value!;
            string email = emailResult.Value!;

            // 2. Check uniqueness via a parameterized query (never string-concatenated SQL).
            if (users.UsernameOrEmailExists(username, email))
                return Results.Conflict(new { error = "Username or email is already registered." });

            // 3. Hash the password (never store or log plaintext passwords).
            var (hash, salt) = PasswordHasher.Hash(passwordResult.Value!);

            // 4. Insert via parameterized query.
            var user = users.Create(username, email, hash, salt);

            return Results.Created($"/api/auth/{user.Id}", new { user.Id, user.Username, user.Role });
        });

        group.MapPost("/login", async (HttpContext ctx, LoginRequest request, SqliteUserRepository users) =>
        {
            var usernameResult = InputValidator.ValidateUsername(request.Username);
            if (!usernameResult.IsValid || string.IsNullOrEmpty(request.Password))
                return Results.Unauthorized(); // deliberately vague — don't reveal which field was wrong

            var user = users.FindByUsername(usernameResult.Value!);

            // Always run the hash comparison even if the user doesn't exist,
            // using a dummy hash/salt, so response timing doesn't reveal
            // whether a given username exists (basic user-enumeration mitigation).
            bool passwordOk = user is not null
                ? PasswordHasher.Verify(request.Password, user.PasswordHash, user.PasswordSalt)
                : PasswordHasher.Verify(request.Password, DummyHash, DummySalt);

            if (user is null || !passwordOk)
                return Results.Unauthorized();

            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new(ClaimTypes.Name, user.Username),
                new(ClaimTypes.Role, user.Role) // RBAC: role drives what the user can access
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

            return Results.Ok(new { user.Username, user.Role });
        });

        group.MapPost("/logout", async (HttpContext ctx) =>
        {
            await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Ok();
        });
    }

    // Pre-computed placeholder hash/salt used only to equalize timing for unknown usernames.
    private static readonly (string DummyHash, string DummySalt) _dummy = PasswordHasher.Hash("not-a-real-password");
    private static string DummyHash => _dummy.DummyHash;
    private static string DummySalt => _dummy.DummySalt;
}
