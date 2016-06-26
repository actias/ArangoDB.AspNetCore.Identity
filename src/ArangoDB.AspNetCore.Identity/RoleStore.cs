using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using ArangoDB.Client;
using Microsoft.AspNetCore.Identity;

namespace ArangoDB.AspNetCore.Identity
{
    public class RoleStore<TUser, TRole, TContext> :
        IQueryableRoleStore<TRole>,
        IRoleClaimStore<TRole>
        where TUser : IdentityUser
        where TRole : IdentityRole
        where TContext : ArangoIdentityContext<TUser, TRole>
    {
        private readonly TContext _context;

        /// <summary>
        ///     Used to generate public API error messages
        /// </summary>
        public IdentityErrorDescriber ErrorDescriber { get; set; }

        public RoleStore(TContext context, IdentityErrorDescriber describer = null)
        {
            _context = context;
            ErrorDescriber = describer ?? new IdentityErrorDescriber();
        }

        public IQueryable<TRole> Roles => _context.Roles;

        public void Dispose()
        {
            // no need to dispose of anything, mongodb handles connection pooling automatically
        }

        public virtual async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            await _context.Database.Collection<TRole>().InsertAsync(role);

            return IdentityResult.Success;
        }

        public virtual async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            var entity = await _context.Roles.FirstOrDefaultAsync(x => x.Id == role.Id);

            if (entity == null)
            {
                throw new NullReferenceException("No role found. Cannot perform update.");
            }

            await _context.Database.ReplaceByIdAsync<TRole>(entity.Key, role);

            return IdentityResult.Success;
        }

        public virtual async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            var entity = await _context.Roles.FirstOrDefaultAsync(x => x.Id == role.Id);

            if (entity == null)
            {
                throw new NullReferenceException("No role found. Cannot perform deletion.");
            }

            await _context.Database.RemoveByIdAsync<TRole>(entity.Key);

            return IdentityResult.Success;
        }

        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Id);
        }

        public Task<string> GetRoleNameAsync(TRole role,CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Name);
        }

        public async Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            var entity = await _context.Roles.FirstOrDefaultAsync(x => x.Id == role.Id);

            if (entity == null)
            {
                throw new NullReferenceException("No role found. Cannot perform update.");
            }

            entity.Name = roleName;

            await _context.Database.UpdateAsync<TRole>(entity);
        }

        public virtual async Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await _context.Roles.FirstOrDefaultAsync(x => x.Id == roleId);
        }

        public virtual async Task<TRole> FindByNameAsync(string normalizedName, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await _context.Roles.FirstOrDefaultAsync(x => x.NormalizedName == normalizedName);
        }

        public virtual Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            return Task.FromResult(role.NormalizedName);
        }

        public virtual Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            role.NormalizedName = normalizedName;

            return Task.FromResult(0);
        }

        public virtual Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult((IList<Claim>)role.Claims.Select(c => c.ToSecurityClaim()).ToList());
        }

        public virtual Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            role.AddClaim(claim);

            return Task.FromResult(0);
        }

        public virtual Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            role.RemoveClaim(claim);

            return Task.FromResult(0);
        }
    }
}