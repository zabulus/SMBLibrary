namespace SMBLibrary.Client
{
    public interface INtlmAuthenticationHelper
    {
        byte[] GetNegotiateMessage(byte[] securityBlob
            , string spn
            , AuthenticationMethod authenticationMethod
        );

        byte[] GetAuthenticateMessage(byte[] securityBuffer
            , string spn
            , AuthenticationMethod authenticationMethod
            , out byte[] mSessionKey
        );
    }
}