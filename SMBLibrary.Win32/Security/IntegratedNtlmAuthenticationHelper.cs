using SMBLibrary.Authentication.NTLM;
using SMBLibrary.Client;

namespace SMBLibrary.Win32.Security
{
    public class IntegratedNtlmAuthenticationHelper : BaseNtlmAuthenticationHelper
    {
        private readonly SecHandle _credentialsHandle;
        private SecHandle _clientContext;

        public IntegratedNtlmAuthenticationHelper()
        {
            _credentialsHandle = SSPIHelper.AcquireNTLMCredentialsHandle();
        }

        protected override byte[] GetType1Message(AuthenticationMethod authenticationMethod)
        {
            return SSPIHelper.GetType1Message(out _clientContext, _credentialsHandle);
        }

        protected override byte[] GetType3Message(ChallengeMessage challengeMessage
            , string spn
            , AuthenticationMethod authenticationMethod
            , out byte[] mSessionKey
        )
        {
            var message = SSPIHelper.GetType3Message(_clientContext, challengeMessage.GetBytes());

            mSessionKey = SSPIHelper.GetSessionKey(_clientContext);
            
            return message;
        }
    }
}