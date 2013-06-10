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
            token.Lifetime = TimeSpan.FromMinutes(2);

            token.ClientIdentifier = accessTokenRequestMessage.ClientIdentifier;

            foreach (string s in accessTokenRequestMessage.Scope)
            {
                token.Scope.Add(s);
            }

            token.User = accessTokenRequestMessage.UserName;
           // token.ExtraData.Add("id_token","thisisthejwt");

            var signCert = LoadCert(Config.ALHAMBRA_AUTHORIZATION);
            token.AccessTokenSigningKey = (RSACryptoServiceProvider)signCert.PrivateKey;

            var encryptCert = LoadCert(Config.ALHAMBRA_RESOURCES);
            token.ResourceServerEncryptionKey = (RSACryptoServiceProvider)encryptCert.PublicKey.Key;

            var accessTokenResult = new AccessTokenResult(token);
            accessTokenResult.AccessToken.ClientIdentifier = accessTokenRequestMessage.ClientIdentifier;
             

            //Page 13 on draft 26 - Open Id Connect Basic Client Profile
            //if (token.Scope.Contains("offline_access"))
            //{
            //    accessTokenResult.AllowRefreshToken = true;
            //}

            accessTokenResult.AllowRefreshToken = true;
            
            return accessTokenResult;
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
                    var allowedCallback =  "/OpenIdConnect/AlhambraCallback";
                    return new ClientDescription(
                                                "secret",
                                                new Uri(allowedCallback),
                                                ClientType.Confidential);
            }
            return null;
        }

        public bool IsAuthorizationValid(DotNetOpenAuth.OAuth2.ChannelElements.IAuthorizationDescription authorization)
        {
            
            if (authorization.ClientIdentifier == "NATURE"
                && authorization.Scope.Count() > 0
                && authorization.Scope.First() == "openid"
                && authorization.User == "user1@alhambra.com")
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