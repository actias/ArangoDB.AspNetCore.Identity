using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using ArangoDB.Client;
using Microsoft.AspNetCore.Identity;

namespace ArangoDB.AspNetCore.Identity
{
    public class UserStore<TUser, TRole, TContext> :
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
        where TUser : IdentityUser
        where TRole : IdentityRole
        where TContext : ArangoIdentityContext<TUser, TRole>
    {
        private const string ValueCannotBeNullOrEmpty = "Value cannot be null or empty.";
        private const string RoleNotFound = "Role {0} does not exist.";


        public TContext Context { get; }

        /// <summary>
        ///     Used to generate public API error messages
        /// </summary>
        public IdentityErrorDescriber ErrorDescriber { get; set; }

        public UserStore(TContext context, IdentityErrorDescriber describer = null)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            Context = context;
            ErrorDescriber = describer ?? new IdentityErrorDescriber();
        }

        public void Dispose()
        {
            // no need to dispose of anything, mongodb handles connection pooling automatically
        }

        public virtual Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.Id);
        }

        public virtual Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.UserName);
        }

        public virtual Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.UserName = userName;

            return Task.FromResult(false);
        }

        public virtual Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.NormalizedUserName);
        }

        public virtual Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.NormalizedUserName = normalizedName;

            return Task.FromResult(false);
        }

        public virtual async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await Context.Database.InsertAsync<TUser>(user);

            return IdentityResult.Success;
        }

        public virtual async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var entity = await Context.Users.FirstOrDefaultAsync(x => x.Id == user.Id);

            if (entity == null)
            {
                throw new NullReferenceException("No role found. Cannot perform update.");
            }

            await Context.Database.ReplaceByIdAsync<TUser>(entity.Key, user);

            return IdentityResult.Success;
        }

        public virtual async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            var entity = await Context.Roles.FirstOrDefaultAsync(x => x.Id == user.Id);

            if (entity == null)
            {
                throw new NullReferenceException("No role found. Cannot perform deletion.");
            }

            await Context.Database.RemoveByIdAsync<TUser>(entity.Key);

            return IdentityResult.Success;
        }

        public virtual async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Context.Users.FirstOrDefaultAsync(x => x.Id == userId);
        }

        public virtual async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Context.Users.FirstOrDefaultAsync(x => x.NormalizedUserName == normalizedUserName);
        }

        public virtual Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            var l = new IdentityUserLogin
            {
                ProviderKey = login.ProviderKey,
                LoginProvider = login.LoginProvider,
                ProviderDisplayName = login.ProviderDisplayName
            };

            user.Logins.Add(l);

            return Task.FromResult(false);
        }

        public virtual Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
            CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            IEnumerable<IdentityUserLogin> loginsToRemove = user.Logins
                .Where(l => l.LoginProvider == loginProvider &&
                            l.ProviderKey == providerKey);

            foreach (var login in loginsToRemove.ToArray())
            {
                user.Logins.Remove(login);
            }

            return Task.FromResult(false);
        }

        public virtual Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            IList<UserLoginInfo>logins = user.Logins
                .Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName))
                .ToList();

            return Task.FromResult(logins);
        }

        public virtual async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Context.Users.FirstOrDefaultAsync(u => u.Logins.Any(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey));
        }

        /// <summary>
        /// Add a user to a role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(nameof(roleName));
            }

            var role = await Context.Roles.FirstOrDefaultAsync(a => a.Name.ToUpper() == roleName.ToUpper());

            if (role == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, RoleNotFound, roleName));
            }

            user.Roles.Add(role);
        }

        /// <summary>
        ///     Remove a user from a role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual Task RemoveFromRoleAsync(TUser user, string roleName,CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(ValueCannotBeNullOrEmpty, nameof(roleName));
            }

            user.Roles.RemoveAll(role => string.Equals(role.Name, roleName, StringComparison.CurrentCultureIgnoreCase));
            return Task.FromResult(false);
        }

        /// <summary>
        /// Get the names of the roles a user is a member of
        /// </summary>
        /// <param name="user"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual Task<IList<string>> GetRolesAsync(TUser user,CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult((IList<string>)user.Roles.Select(role => role.Name).ToList());
        }

        /// <summary>
        /// Returns true if the user is in the named role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(ValueCannotBeNullOrEmpty, nameof(roleName));
            }

            return Task.FromResult(user.Roles.Any(role => role.Name.ToUpper() == roleName.ToUpper()));
        }

        public virtual Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult((IList<Claim>)user.Claims.Select(c => c.ToSecurityClaim()).ToList());
        }

        public virtual Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            foreach (var claim in claims)
            {
                user.AddClaim(claim);
            }

            return Task.FromResult(false);
        }

        public virtual Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (newClaim == null)
            {
                throw new ArgumentNullException(nameof(newClaim));
            }

            user.ReplaceClaim(claim, newClaim);

            return Task.FromResult(false);
        }

        public virtual Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            foreach (var claim in claims)
            {
                user.RemoveClaim(claim);
            }

            return Task.FromResult(false);
        }

        public virtual Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.PasswordHash = passwordHash;

            return Task.FromResult(false);
        }

        public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PasswordHash != null);
        }

        public virtual Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.SecurityStamp = stamp;

            return Task.FromResult(false);
        }

        public virtual Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.SecurityStamp);
        }

        public virtual Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.Email = email;

            return Task.FromResult(false);
        }

        public virtual Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.Email);
        }

        public virtual Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.NormalizedEmail);
        }

        public virtual Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.NormalizedEmail = normalizedEmail;

            return Task.FromResult(0);
        }

        public virtual Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.EmailConfirmed);
        }

        public virtual Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.EmailConfirmed = confirmed;

            return Task.FromResult(false);
        }

        public virtual async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await Context.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail);
        }

        public virtual Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.LockoutEnd);
        }

        public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.LockoutEnd = lockoutEnd;

            return Task.FromResult(false);
        }

        Task<DateTimeOffset?> IUserLockoutStore<TUser>.GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.LockoutEnd);
        }

        public virtual Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.AccessFailedCount++;

            return Task.FromResult(user.AccessFailedCount);
        }

        public virtual Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.AccessFailedCount = 0;

            return Task.FromResult(false);
        }

        public virtual Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.AccessFailedCount);
        }

        public virtual Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.LockoutEnabled);
        }

        public virtual Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.LockoutEnabled = enabled;

            return Task.FromResult(false);
        }

        public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.PhoneNumber = phoneNumber;

            return Task.FromResult(false);
        }

        public virtual Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PhoneNumber);
        }

        public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed,
            CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.PhoneNumberConfirmed = confirmed;

            return Task.FromResult(false);
        }

        public IQueryable<TUser> Users => Context.Users.AsQueryable();

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.TwoFactorEnabled = enabled;

            return Task.FromResult(false);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.TwoFactorEnabled);
        }

        /// <summary>
        /// Get all users with given claim
        /// </summary>
        /// <param name="claim"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            return await Context.Users
                .Where(x => x.Claims.Any(y => y.ClaimValue == claim.Value && y.ClaimType == claim.Type))
                .ToListAsync();
        }

        /// <summary>
        /// Get all users in given role
        /// </summary>
        /// <param name="roleName"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrEmpty(roleName))
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            return await Context.Users
                .Where(x => x.Roles.Any(r => r.NormalizedName == roleName))
                .ToListAsync();
        }
    }
}