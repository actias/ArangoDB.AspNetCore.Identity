using System;
using System.Collections.Generic;
using System.Security.Claims;
using ArangoDB.Client;

namespace ArangoDB.AspNetCore.Identity
{
    /// <summary>
    /// Represents a Role entity
    /// </summary>
    public class IdentityRole
    {
        public IdentityRole()
        {
            Id = Guid.NewGuid().ToString("N");
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="roleName"></param>
        public IdentityRole(string roleName) : this()
        {
            Name = roleName;
        }

        /// <summary>
        /// Database key for the role. This is relative to the collection
        /// and could be duplicated between shards. Do not use this as the
        /// unique for your roles.
        /// </summary>
        [DocumentProperty(Identifier = IdentifierType.Key)]
        public string Key;

        /// <summary>
        /// Role Id
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// Role name
        /// </summary>
        public string Name { get; set; }
        public string NormalizedName { get; set; }

        /// <summary>
        /// A random value that should change whenever a role is persisted to the store
        /// </summary>
        public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Collection of claims in the role
        /// </summary>
        public List<Claim> Claims { get; } = new List<Claim>();
    }
}