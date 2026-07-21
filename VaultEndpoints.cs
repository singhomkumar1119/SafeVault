using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using SafeVault.Web.Data;
using SafeVault.Web.Models;
using SafeVault.Web.Services;

namespace SafeVault.Web.Endpoints;

public static class VaultEndpoints
{
    public static void MapVaultEndpoints(this WebApplication app)
    {
        var vault = app.MapGroup("/api/vault").RequireAuthorization(); // any authenticated user

        vault.MapGet("/notes", (ClaimsPrincipal user, SqliteNoteRepository notes) =>
        {
            int userId = GetUserId(user);
            var mine = notes.GetForUser(userId);

            // Output-encode every field before it could ever be rendered as HTML.
            // This is what stops a stored XSS payload (e.g. "<script>...</script>")
            // saved by a note from executing when the note is displayed.
            var safe = mine.Select(n => new
            {
                n.Id,
                Text = InputValidator.EncodeForOutput(n.Text),
                n.CreatedUtc
            });

            return Results.Ok(safe);
        });

        vault.MapPost("/notes", (ClaimsPrincipal user, CreateNoteRequest request, SqliteNoteRepository notes) =>
        {
            var textResult = InputValidator.ValidateNoteText(request.Text);
            if (!textResult.IsValid) return Results.BadRequest(new { error = textResult.Error });

            int userId = GetUserId(user);
            var note = notes.Create(userId, textResult.Value!);

            return Results.Created($"/api/vault/notes/{note.Id}", new
            {
                note.Id,
                Text = InputValidator.EncodeForOutput(note.Text),
                note.CreatedUtc
            });
        });

        // RBAC: only users with the "Admin" role reach this group.
        var admin = app.MapGroup("/api/admin").RequireAuthorization(policy => policy.RequireRole("Admin"));

        admin.MapGet("/users", (SqliteUserRepository users) =>
        {
            var all = users.GetAll().Select(u => new { u.Id, u.Username, u.Email, u.Role });
            return Results.Ok(all);
        });

        admin.MapDelete("/users/{id:int}", (int id, ClaimsPrincipal caller, SqliteUserRepository users) =>
        {
            if (id == GetUserId(caller))
                return Results.BadRequest(new { error = "Admins cannot delete their own account here." });

            bool deleted = users.Delete(id);
            return deleted ? Results.NoContent() : Results.NotFound();
        });
    }

    private static int GetUserId(ClaimsPrincipal user) =>
        int.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
}
