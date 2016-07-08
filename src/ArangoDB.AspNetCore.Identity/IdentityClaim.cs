using System.Security.Claims;

namespace ArangoDB.AspNetCore.Identity
{
    public class IdentityClaim
    {
        public IdentityClaim(){}

        public IdentityClaim(Claim claim)
        {
            Type = claim.Type;
            Value = claim.Value;
        }

        public string Type { get; set; }
        public string Value { get; set; }

        public Claim ToSecurityClaim()
        {
            return new Claim(Type, Value);
        }
    }
}
