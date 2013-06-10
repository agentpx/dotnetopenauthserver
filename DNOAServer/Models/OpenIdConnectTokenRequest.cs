using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Web;

namespace DNOAServer.Models
{
    public class OpenIdConnectTokenRequest
    {
        [DataMember(Name = "grant_type")]
        public string grant_type { get; set; }

        [DataMember(Name = "code")]
        public string code { get; set; }

        [DataMember(Name = "redirect_uri")]
        public string redirect_uri { get; set; }

    }
}