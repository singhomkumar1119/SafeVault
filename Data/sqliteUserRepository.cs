using Microsoft.Data.Sqlite;
using SafeVault.Web.Models;

namespace SafeVault.Web.Data;

/// <summary>
/// All queries in this class use parameterized SQL (SqliteParameter / @placeholders).
/// User-supplied values are NEVER concatenated or interpolated into a SQL string.
///
/// --- BEFORE (vulnerable to SQL injection - do not use) ---
///   var cmd = connection.CreateCommand();
///   cmd.CommandText = $"SELECT * FROM Users WHERE Username = '{username}' AND PasswordHash = '{passwordHash}'";
///   // An attacker could submit username = "admin' -- " to comment out the
///   // password check entirely, or "' OR '1'='1" to match every row.
///
/// --- AFTER (fixed, used below) ---
///   cmd.CommandText = "SELECT * FROM Users WHERE Username = @username;";
///   cmd.Parameters.AddWithValue("@username", username);
///   // The database driver sends the value separately from the SQL text, so it
///   // can never change the meaning of the query, no matter what characters
///   // (quotes, --, ;, OR, etc.) it contains.
/// </summary>
public class SqliteUserRepository
{
    private readonly string _connectionString;

    public SqliteUserRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public User? FindByUsername(string username)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT Id, Username, Email, PasswordHash, PasswordSalt, Role FROM Users WHERE Username = @username;";
        cmd.Parameters.AddWithValue("@username", username);

        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;

        return Map(reader);
    }

    public bool UsernameOrEmailExists(string username, string email)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM Users WHERE Username = @username OR Email = @email;";
        cmd.Parameters.AddWithValue("@username", username);
        cmd.Parameters.AddWithValue("@email", email);

        long count = (long)cmd.ExecuteScalar()!;
        return count > 0;
    }

    public User Create(string username, string email, string passwordHash, string passwordSalt, string role = "User")
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO Users (Username, Email, PasswordHash, PasswordSalt, Role)
            VALUES (@username, @email, @hash, @salt, @role);
            SELECT last_insert_rowid();
            """;
        cmd.Parameters.AddWithValue("@username", username);
        cmd.Parameters.AddWithValue("@email", email);
        cmd.Parameters.AddWithValue("@hash", passwordHash);
        cmd.Parameters.AddWithValue("@salt", passwordSalt);
        cmd.Parameters.AddWithValue("@role", role);

        long id = (long)cmd.ExecuteScalar()!;

        return new User
        {
            Id = (int)id,
            Username = username,
            Email = email,
            PasswordHash = passwordHash,
            PasswordSalt = passwordSalt,
            Role = role
        };
    }

    public List<User> GetAll()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT Id, Username, Email, PasswordHash, PasswordSalt, Role FROM Users ORDER BY Id;";

        var users = new List<User>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            users.Add(Map(reader));
        }
        return users;
    }

    public bool Delete(int id)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var cmd = connection.CreateCommand();
        cmd.CommandText = "DELETE FROM Users WHERE Id = @id;";
        cmd.Parameters.AddWithValue("@id", id);

        return cmd.ExecuteNonQuery() > 0;
    }

    private static User Map(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt32(0),
        Username = reader.GetString(1),
        Email = reader.GetString(2),
        PasswordHash = reader.GetString(3),
        PasswordSalt = reader.GetString(4),
        Role = reader.GetString(5)
    };
}
