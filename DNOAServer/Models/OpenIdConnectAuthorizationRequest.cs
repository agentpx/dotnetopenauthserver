using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Web;

namespace DNOAServer.Models
{

    [DataContract]
    public class OpenIdConnectAuthorizationRequest
    {
        [DataMember(Name = "response_type")]
        public string response_type { get; set; }

        [DataMember(Name = "client_id")]
        public string client_id { get; set; }

        //public string ClientSecret { get; set; }

        [DataMember(Name = "redirect_uri")]
        public string redirect_uri { get; set; }

        [DataMember(Name = "scope")]
        public string scope { get; set; }

        [DataMember(Name = "state")]
        public string state { get; set; }

    }
}