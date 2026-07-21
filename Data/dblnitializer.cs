using Microsoft.Data.Sqlite;
using SafeVault.Web.Services;

namespace SafeVault.Web.Data;

public static class DbInitializer
{
    public static void Initialize(string connectionString)
    {
        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        var createUsers = connection.CreateCommand();
        createUsers.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Email TEXT NOT NULL UNIQUE,
                PasswordHash TEXT NOT NULL,
                PasswordSalt TEXT NOT NULL,
                Role TEXT NOT NULL DEFAULT 'User'
            );
            """;
        createUsers.ExecuteNonQuery();

        var createNotes = connection.CreateCommand();
        createNotes.CommandText = """
            CREATE TABLE IF NOT EXISTS Notes (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                UserId INTEGER NOT NULL,
                Text TEXT NOT NULL,
                CreatedUtc TEXT NOT NULL,
                FOREIGN KEY (UserId) REFERENCES Users(Id)
            );
            """;
        createNotes.ExecuteNonQuery();

        // Seed a default admin account for demo/testing purposes only.
        // NOTE: change this password immediately in any real deployment.
        var checkAdmin = connection.CreateCommand();
        checkAdmin.CommandText = "SELECT COUNT(*) FROM Users WHERE Username = @username;";
        checkAdmin.Parameters.AddWithValue("@username", "admin");
        long existing = (long)checkAdmin.ExecuteScalar()!;

        if (existing == 0)
        {
            var (hash, salt) = PasswordHasher.Hash("ChangeMe123!");

            var insertAdmin = connection.CreateCommand();
            insertAdmin.CommandText = """
                INSERT INTO Users (Username, Email, PasswordHash, PasswordSalt, Role)
                VALUES (@username, @email, @hash, @salt, @role);
                """;
            insertAdmin.Parameters.AddWithValue("@username", "admin");
            insertAdmin.Parameters.AddWithValue("@email", "admin@safevault.local");
            insertAdmin.Parameters.AddWithValue("@hash", hash);
            insertAdmin.Parameters.AddWithValue("@salt", salt);
            insertAdmin.Parameters.AddWithValue("@role", "Admin");
            insertAdmin.ExecuteNonQuery();
        }
    }
}
