using SMBLibrary.Authentication.NTLM;

namespace SMBLibrary.Client
{
    internal class UserProvidedNtlmAuthenticationHelper : BaseNtlmAuthenticationHelper
    {
        private readonly string _domainName;
        private readonly string _userName;
        private readonly string _password;

        public UserProvidedNtlmAuthenticationHelper(string domainName
            , string userName
            , string password
        )
        {
            _domainName = domainName;
            _userName = userName;
            _password = password;
        }

        protected override byte[] GetType1Message(AuthenticationMethod authenticationMethod
        )
        {
            return NTLMAuthenticationHelper.GetType1Message(_domainName, authenticationMethod).GetBytes();
        }

        protected override byte[] GetType3Message(ChallengeMessage challengeMessage
            , string spn
            , AuthenticationMethod authenticationMethod
            , out byte[] mSessionKey
        )
        {
            return NTLMAuthenticationHelper.GetType3Message(_domainName, _userName, _password, spn, authenticationMethod, out mSessionKey
                , challengeMessage
            ).GetBytes();
        }
    }
}