using ArangoDB.Client;

namespace ArangoDB.AspNetCore.Identity
{
    public interface IStore
    {
        IArangoDatabase Database { get; set; }
        IArangoDatabase GetDatabaseFromSqlStyle(string connectionString);
    }
}
