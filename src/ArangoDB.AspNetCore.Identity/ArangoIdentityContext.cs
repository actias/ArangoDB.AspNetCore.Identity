using ArangoDB.Client;
using ArangoDB.Client.Linq;

namespace ArangoDB.AspNetCore.Identity
{
    public class ArangoIdentityContext<TUser, TRole>
        where TUser : IdentityUser
        where TRole : IdentityRole
    {
        public ArangoDatabase Database { get; set; }
        public AqlQueryable<TUser> Users { get; set; }
        public AqlQueryable<TRole> Roles { get; set; }
    }
}