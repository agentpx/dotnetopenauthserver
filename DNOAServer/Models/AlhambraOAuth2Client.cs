using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Web;

namespace DNOAServer.Models
{
    public class AlhambraOAuth2Client
    {
        [DataMember(Name = "client_id")]
        public string Identifier { get; set; }

        [DataMember(Name = "client_secret")]
        public string Secret { get; set; }
    }
}