using DotNetOpenAuth.OAuth2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace DNOAServer.Code
{
    public class AlhambraAuthorizationServerHost : IAuthorizationServerHost
    {
        public AutomatedAuthorizationCheckResponse CheckAuthorizeClientCredentialsGrant(DotNetOpenAuth.OAuth2.Messages.IAccessTokenRequest accessRequest)
        {
            throw new NotImplementedException();
        }

        public AutomatedUserAuthorizationCheckResponse CheckAuthorizeResourceOwnerCredentialGrant(string userName, string password, DotNetOpenAuth.OAuth2.Messages.IAccessTokenRequest accessRequest)
        {
            throw new NotImplementedException();
        }

        public AccessTokenResult CreateAccessToken(DotNetOpenAuth.OAuth2.Messages.IAccessTokenRequest accessTokenRequestMessage)
        {
            var token = new AuthorizationServerAccessToken();
            token.Lifetime = TimeSpan.FromMinutes(10);

            var signCert = LoadCert(Config.STS_CERT);
            token.AccessTokenSigningKey = (RSACryptoServiceProvider)signCert.PrivateKey;

            var encryptCert = LoadCert(Config.SERVICE_CERT);
            token.ResourceServerEncryptionKey = (RSACryptoServiceProvider)encryptCert.PublicKey.Key;

            var result = new AccessTokenResult(token);

            return result;
        }

        public DotNetOpenAuth.Messaging.Bindings.ICryptoKeyStore CryptoKeyStore
        {
            get { return new InMemoryCryptoKeyStore(); }
        }

        public IClientDescription GetClient(string clientIdentifier)
        {
            switch (clientIdentifier)
            {
                case "NATURE":
                    var allowedCallback = "http://localhost:8080/OAuth2/Callback";
                    return new ClientDescription(
                                                "data!",
                                                new Uri(allowedCallback),
                                                ClientType.Confidential);
            }
            return null;
        }

        public bool IsAuthorizationValid(DotNetOpenAuth.OAuth2.ChannelElements.IAuthorizationDescription authorization)
        {
            if (authorization.ClientIdentifier == "NATURE"
                && authorization.Scope.Count() == 1
                && authorization.Scope.First() == "openid"
                && authorization.User == "User1")
            {
                return true;
            }
            return false;
        }

        public DotNetOpenAuth.Messaging.Bindings.INonceStore NonceStore
        {
            get { return new DummyNonceStore(); }
        }

        #region Helpers

        private static X509Certificate2 LoadCert(string thumbprint)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            if (certs.Count == 0) throw new Exception("Could not find cert");
            var cert = certs[0];
            return cert;
        }

        #endregion

    }
}