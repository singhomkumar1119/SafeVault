namespace SafeVault.Web.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string PasswordSalt { get; set; } = string.Empty;

    /// <summary>Role-based access control: "User" or "Admin".</summary>
    public string Role { get; set; } = "User";
}

public record RegisterRequest(string Username, string Email, string Password);
public record LoginRequest(string Username, string Password);

public class Note
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Text { get; set; } = string.Empty;
    public DateTime CreatedUtc { get; set; }
}

public record CreateNoteRequest(string Text);
