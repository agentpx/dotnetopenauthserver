using Microsoft.IdentityModel.Tokens.JWT;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.ServiceModel.Security.Tokens;
using System.Web;

namespace DNOAServer.Code
{
    public static class AlhambraJwtTokenManager
    {
        public static bool IsTokenValid(JWTSecurityToken jwt, string audience, string issuer, byte[] signature)
        {
            bool result = false;

            // Create token validation parameters for the signed JWT
            // This object will be used to verify the cryptographic signature of the received JWT
            TokenValidationParameters validationParams =
                new TokenValidationParameters()
                {
                    AllowedAudience = audience,
                    ValidIssuer = issuer,
                    ValidateExpiration = true,
                    ValidateNotBefore = false,
                    ValidateIssuer = true,
                    ValidateSignature = true,
                    //SigningToken = null

                    SigningToken = new BinarySecretSecurityToken(signature)
                };

          

            // Create JWT handler
            // This object is used to write/sign/decode/validate JWTs
            JWTSecurityTokenHandler jwtHandler = new JWTSecurityTokenHandler();
            
            // Serialize the JWT
            // This is how our JWT looks on the wire: <Base64UrlEncoded header>.<Base64UrlEncoded body>.<signature>
            string jwtOnTheWire = jwtHandler.WriteToken(jwt);

            try
            {
                // Validate the token signature (we provide the shared symmetric key in `validationParams`)
                // This will throw if the signature does not validate
               // jwtHandler.ValidateToken(jwtOnTheWire, validationParams);
                jwtHandler.ValidateToken(jwt, validationParams);
                result = true;
            }
            catch
            {
                result = false;
            }
            return result;
        }

        public static bool IsTokenValid(JWTSecurityToken jwt, string audience, string issuer)
        {
            bool result = false;

            // Create token validation parameters for the signed JWT
            // This object will be used to verify the cryptographic signature of the received JWT
            TokenValidationParameters validationParams =
                new TokenValidationParameters()
                {
                    AllowedAudience = audience,
                    ValidIssuer = issuer,
                    ValidateExpiration = true,
                    ValidateNotBefore = false,
                    ValidateIssuer = true,
                    ValidateSignature = false
                };



            // Create JWT handler
            // This object is used to write/sign/decode/validate JWTs
            JWTSecurityTokenHandler jwtHandler = new JWTSecurityTokenHandler();

            // Serialize the JWT
            // This is how our JWT looks on the wire: <Base64UrlEncoded header>.<Base64UrlEncoded body>.<signature>
            string jwtOnTheWire = jwtHandler.WriteToken(jwt);

            try
            {
                // Validate the token signature (we provide the shared symmetric key in `validationParams`)
                // This will throw if the signature does not validate
                // jwtHandler.ValidateToken(jwtOnTheWire, validationParams);
                jwtHandler.ValidateToken(jwt, validationParams);
                result = true;
            }
            catch
            {
                result = false;
            }
            return result;
        }

        public static string DecodeJWT(JWTSecurityToken jwt)
        {
            // Create JWT handler
            // This object is used to write/sign/decode/validate JWTs
            JWTSecurityTokenHandler jwtHandler = new JWTSecurityTokenHandler();

            // Serialize the JWT
            // This is how our JWT looks on the wire: <Base64UrlEncoded header>.<Base64UrlEncoded body>.<signature>
            string jwtOnTheWire = jwtHandler.WriteToken(jwt);

            // Parse JWT from the Base64UrlEncoded wire form (<Base64UrlEncoded header>.<Base64UrlEncoded body>.<signature>)
            JWTSecurityToken parsedJwt = jwtHandler.ReadToken(jwtOnTheWire) as JWTSecurityToken;

            return parsedJwt.ToString();
        }

        public static string EncodeJWT(JWTSecurityToken jwt)
        {
            // Create JWT handler
            // This object is used to write/sign/decode/validate JWTs
            JWTSecurityTokenHandler jwtHandler = new JWTSecurityTokenHandler();

            // Serialize the JWT
            // This is how our JWT looks on the wire: <Base64UrlEncoded header>.<Base64UrlEncoded body>.<signature>
            string jwtOnTheWire = jwtHandler.WriteToken(jwt);

            return jwtOnTheWire;
        }

        public static JWTSecurityToken GenerateJwtToken(string issuer, string subject, string audience, DateTime expires, byte[] signature)
        {

            DateTime issuedAt = DateTime.UtcNow;

            // Create signing credentials for the signed JWT.
            // This object is used to cryptographically sign the JWT by the issuer.
            SigningCredentials signingCredentials = new SigningCredentials(
                                            new InMemorySymmetricSecurityKey(signature),
                                            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                                            "http://www.w3.org/2001/04/xmlenc#sha256");

            // Create a simple JWT claim set
            IList<Claim> claims = new List<Claim>() { 
                                                        new Claim("sub", subject),
                                                        new Claim("iat", ToUnixTime(issuedAt).ToString()) };

            // Create a JWT with signing credentials and lifetime of 12 hours
            JWTSecurityToken jwt = new JWTSecurityToken(issuer, audience, claims, signingCredentials, issuedAt, expires);
            
            return jwt;
        }

        public static JWTSecurityToken GenerateJwtToken(string issuer, string subject, string audience, DateTime expires)
        {

            DateTime issuedAt = DateTime.UtcNow;

            // Create a simple JWT claim set
            IList<Claim> claims = new List<Claim>() { 
                                                        new Claim("sub", subject),
                                                        new Claim("iat", ToUnixTime(issuedAt).ToString()) };

            // Create a JWT with signing credentials and lifetime of 12 hours
            JWTSecurityToken jwt = new JWTSecurityToken(issuer, audience, claims, null, issuedAt, expires);

            return jwt;
        }

        private static long ToUnixTime(DateTime date)
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); //small fix on EPOCH (add 1 second) to avoid iat being later than nbf
            return Convert.ToInt64((date.ToUniversalTime() - epoch).TotalSeconds);
        }

        public static byte[] GenerateSymmetricKeyForHmacSha256()
        {
            // Generate symmetric key for HMAC-SHA256 signature
            RNGCryptoServiceProvider cryptoProvider = new RNGCryptoServiceProvider();
            byte[] keyForHmacSha256 = new byte[64];
            cryptoProvider.GetNonZeroBytes(keyForHmacSha256);
            return keyForHmacSha256;
        }

    }
}