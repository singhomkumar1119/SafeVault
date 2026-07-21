using Microsoft.Data.Sqlite;
using SafeVault.Web.Models;

namespace SafeVault.Web.Data;

/// <summary>
/// Notes are stored exactly as typed (parameterized INSERT, so no SQL
/// injection risk). The stored-XSS defense is applied separately, at the
/// point where a note's text is rendered back out — see
/// InputValidator.EncodeForOutput, used in Endpoints/VaultEndpoints.cs.
/// </summary>
public class SqliteNoteRepository
{
    private readonly string _connectionString;

    public SqliteNoteRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public Note Create(int userId, string text)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var createdUtc = DateTime.UtcNow;

        var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO Notes (UserId, Text, CreatedUtc)
            VALUES (@userId, @text, @createdUtc);
            SELECT last_insert_rowid();
            """;
        cmd.Parameters.AddWithValue("@userId", userId);
        cmd.Parameters.AddWithValue("@text", text);
        cmd.Parameters.AddWithValue("@createdUtc", createdUtc.ToString("O"));

        long id = (long)cmd.ExecuteScalar()!;

        return new Note { Id = (int)id, UserId = userId, Text = text, CreatedUtc = createdUtc };
    }

    public List<Note> GetForUser(int userId)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT Id, UserId, Text, CreatedUtc FROM Notes WHERE UserId = @userId ORDER BY Id DESC;";
        cmd.Parameters.AddWithValue("@userId", userId);

        var notes = new List<Note>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            notes.Add(new Note
            {
                Id = reader.GetInt32(0),
                UserId = reader.GetInt32(1),
                Text = reader.GetString(2),
                CreatedUtc = DateTime.Parse(reader.GetString(3))
            });
        }
        return notes;
    }
}
