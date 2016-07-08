using System.Linq;
using ArangoDB.Client;
using Microsoft.AspNetCore.Identity;

namespace ArangoDB.AspNetCore.Identity
{
    /// <summary>
    ///     Class UserStore.
    /// </summary>
    /// <typeparam name="TUser">The type of the t user.</typeparam>
    public partial class UserStore<TUser> :
        Store,
        IUserLoginStore<TUser>,
        IUserRoleStore<TUser>,
        IUserClaimStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,
        IUserEmailStore<TUser>,
        IUserLockoutStore<TUser>,
        IUserPhoneNumberStore<TUser>,
        IQueryableUserStore<TUser>,
        IUserTwoFactorStore<TUser>
    {
        /// <summary>
        ///     The _disposed
        /// </summary>
        private bool _disposed;

        /// <summary>
        /// Retrieves all users from the database.
        /// </summary>
        public IQueryable<TUser> Users => Database.Query<TUser>();

        /// <summary>
        ///     Initializes a new instance of the <see cref="UserStore{TUser}" /> class.
        /// </summary>
        /// <param name="url">The URL of the database.</param>
        /// <param name="database">Name of the database.</param>
        public UserStore(string url, string database)
        {
            Database = new ArangoDatabase(url, database);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserStore{TUser}"/> class using a already initialized Arango Database.
        /// </summary>
        /// <param name="arangoDatabase">The Arango database.</param>
        public UserStore(IArangoDatabase arangoDatabase)
        {
            Database = arangoDatabase;
        }
    }
}
        