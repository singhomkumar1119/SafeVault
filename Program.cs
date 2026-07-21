using Microsoft.AspNetCore.Authentication.Cookies;
using SafeVault.Web.Data;
using SafeVault.Web.Endpoints;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("SafeVaultDb")
    ?? "Data Source=safevault.db";

// Repositories (parameterized-query data access — see Data/*.cs)
builder.Services.AddSingleton(new SqliteUserRepository(connectionString));
builder.Services.AddSingleton(new SqliteNoteRepository(connectionString));

// Authentication: cookie-based sign-in. Role claim set at login drives RBAC.
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;                                   // not readable from JS -> mitigates XSS token theft
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;          // HTTPS only
        options.Cookie.SameSite = SameSiteMode.Strict;                    // mitigates CSRF
        options.ExpireTimeSpan = TimeSpan.FromHours(2);
        options.SlidingExpiration = true;
        options.Events.OnRedirectToLogin = ctx =>
        {
            // For an API, return 401 JSON instead of redirecting to a login page.
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    });

// Authorization policies (RBAC).
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

var app = builder.Build();

DbInitializer.Initialize(connectionString);

// Basic security headers.
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    await next();
});

app.UseAuthentication();
app.UseAuthorization();

app.MapAuthEndpoints();
app.MapVaultEndpoints();

app.MapGet("/", () => Results.Ok(new
{
    service = "SafeVault",
    status = "running",
    endpoints = new[]
    {
        "POST /api/auth/register",
        "POST /api/auth/login",
        "POST /api/auth/logout",
        "GET  /api/vault/notes (auth required)",
        "POST /api/vault/notes (auth required)",
        "GET  /api/admin/users (Admin role required)",
        "DELETE /api/admin/users/{id} (Admin role required)"
    }
}));

app.Run();

// Exposed for WebApplicationFactory-based integration tests.
public partial class Program { }
