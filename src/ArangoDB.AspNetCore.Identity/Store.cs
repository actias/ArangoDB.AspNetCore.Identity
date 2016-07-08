using System;
using ArangoDB.Client;

namespace ArangoDB.AspNetCore.Identity
{
    public class Store : IStore
    {
        public IArangoDatabase Database { get; set; }

        /// <summary>
        ///     Gets the database from connection string.
        /// </summary>
        /// <param name="connectionString">The connection string.</param>
        /// <returns>MongoDatabase.</returns>
        /// <exception cref="System.Exception">No database name specified in connection string</exception>
        public IArangoDatabase GetDatabaseFromSqlStyle(string connectionString)
        {
            if (string.IsNullOrEmpty(connectionString))
                throw new ArgumentNullException(connectionString);

            var server = "";
            var database = "";
            var username = "";
            var password = "";

            foreach (var item in connectionString.Split(';'))
            {
                if (!item.Contains("=")) continue;

                var split = item.Split('=');
                var key = split[0].ToLower();
                var value = split[1];

                switch (key)
                {
                    case "server":
                        server = value;
                        break;
                    case "database":
                        database = value;
                        break;
                    case "user id":
                        username = value;
                        break;
                    case "password":
                        password = value;
                        break;
                }
            }

            if (string.IsNullOrEmpty(server))
                throw new ArgumentException("Url cannot be blank in connection string");

            Uri uri;

            if (!Uri.TryCreate(server, UriKind.Absolute, out uri))
                throw new ArgumentException("Url is in an incorrect format");

            if (string.IsNullOrEmpty(server))
                throw new ArgumentException("Database cannot be blank connection string");

            if ((!string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password))
                || (!string.IsNullOrEmpty(password) && string.IsNullOrEmpty(username)))
                throw new ArgumentException("User and Password must both have values");

            var userInfo = string.IsNullOrEmpty(username) ? "" : $"{username}:{password}@";

            server = $"{uri.Scheme}://{userInfo}{uri.Host}:{uri.Port}";

            return new ArangoDatabase(server, database);
        }
    }
}
