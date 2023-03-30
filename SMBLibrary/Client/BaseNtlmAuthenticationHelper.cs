using System.Collections.Generic;
using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.Authentication.NTLM;

namespace SMBLibrary.Client
{
    public abstract class BaseNtlmAuthenticationHelper : INtlmAuthenticationHelper
    {
        public byte[] GetNegotiateMessage(byte[] securityBlob
            , string spn
            , AuthenticationMethod authenticationMethod
        )
        {
            bool useGSSAPI = false;
            if (securityBlob.Length > 0)
            {
                SimpleProtectedNegotiationTokenInit inputToken = null;
                try
                {
                    inputToken = SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, true) as SimpleProtectedNegotiationTokenInit;
                }
                catch
                {
                }

                if (inputToken == null || !NTLMAuthenticationHelper.ContainsMechanism(inputToken, GSSProvider.NTLMSSPIdentifier))
                {
                    return null;
                }
                useGSSAPI = true;
            }

            byte[] messageBytes = this.GetType1Message(authenticationMethod);
            if (useGSSAPI)
            {
                SimpleProtectedNegotiationTokenInit outputToken = new SimpleProtectedNegotiationTokenInit();
                outputToken.MechanismTypeList = new List<byte[]>();
                outputToken.MechanismTypeList.Add(GSSProvider.NTLMSSPIdentifier);
                outputToken.MechanismToken = messageBytes;
                return outputToken.GetBytes(true);
            }

            return messageBytes;
        }

        protected abstract byte[] GetType1Message(AuthenticationMethod authenticationMethod);

        public byte[] GetAuthenticateMessage(byte[] securityBlob
            , string spn
            , AuthenticationMethod authenticationMethod
            , out byte[] mSessionKey
        )
        {
            mSessionKey = null;
            bool useGSSAPI = false;
            SimpleProtectedNegotiationTokenResponse inputToken = null;
            try
            {
                inputToken = SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, false) as SimpleProtectedNegotiationTokenResponse;
            }
            catch
            {
            }

            ChallengeMessage challengeMessage;
            if (inputToken != null)
            {
                challengeMessage = NTLMAuthenticationHelper.GetChallengeMessage(inputToken.ResponseToken);
                useGSSAPI = true;
            }
            else
            {
                challengeMessage = NTLMAuthenticationHelper.GetChallengeMessage(securityBlob);
            }

            if (challengeMessage == null)
            {
                return null;
            }

            var message = GetType3Message(challengeMessage, spn, authenticationMethod, out mSessionKey);
            
            if (useGSSAPI)
            {
                SimpleProtectedNegotiationTokenResponse outputToken = new SimpleProtectedNegotiationTokenResponse();
                outputToken.ResponseToken = message;
                return outputToken.GetBytes();
            }
            else
            {
                return message;
            }
        }

        protected abstract byte[] GetType3Message(ChallengeMessage challengeMessage
            , string spn
            , AuthenticationMethod authenticationMethod
            , out byte[] mSessionKey
        );
    }
}