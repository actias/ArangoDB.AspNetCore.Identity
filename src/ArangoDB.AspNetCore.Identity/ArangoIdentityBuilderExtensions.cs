using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ArangoDB.AspNetCore.Identity
{
    public static class ArangoIdentityBuilderExtensions
    {
        public static IdentityBuilder AddMongoStores<TContext, TUser, TRole>(this IdentityBuilder builder)
            where TUser : IdentityUser
            where TRole : IdentityRole
            where TContext : ArangoIdentityContext<TUser, TRole>
        {
            builder.Services.Add(ArangoIdentityServices.GetDefaultServices(builder.UserType, builder.RoleType, typeof (TContext)));
            return builder;
        }
    }
}