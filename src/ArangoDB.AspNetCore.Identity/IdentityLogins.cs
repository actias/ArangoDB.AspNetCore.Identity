using Microsoft.AspNetCore.Identity;

namespace ArangoDB.AspNetCore.Identity
{
    public class IdentityLogin
    {
        public string LoginProvider { get; set; }
        public string ProviderKey { get; set; }

        public IdentityLogin() {}

        public IdentityLogin(UserLoginInfo info)
        {
            LoginProvider = info.LoginProvider;
            ProviderKey = info.ProviderKey;
        }

        public UserLoginInfo ToUserLoginInfo()
        {
            return new UserLoginInfo(LoginProvider, ProviderKey, "");
        }
    }
}
