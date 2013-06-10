using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DNOAServer.Code
{
    public static class OpenIdConnectScopes
    {

        /// <summary>
        /// Complies with the OpenId Connect Protocol
        /// </summary>
        public const string OpenId = "openid";

        /// <summary>
        /// Gain read-only access to Unique Identifier
        /// </summary>
        public const string Subject = "sub";

        /// <summary>
        /// Gain read-only access to Full Name
        /// </summary>
        public const string FullName = "name";

        /// <summary>
        /// Gain read-only access to First Name
        /// </summary>
        public const string FirstName = "given_name";

        /// <summary>
        /// Gain read-only access to Last Name
        /// </summary>
        public const string LastName = "family_name";

        /// <summary>
        /// Gain read-only access to basic profile information.
        /// </summary>
        public const string Profile = "profile";

        /// <summary>
        /// Gain read-only access to the user's email address.
        /// </summary>
        public const string Email = "email";

        /// <summary>
        /// This scope requests that an OAuth 2.0 Refresh Token be 
        /// issued that can be used to obtain an access token that grants access to the End-User's
        /// UserInfo EndPoint even when the user is not present
        /// </summary>
        public const string OfflineAccess = "offline_access";
    }
}