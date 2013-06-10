using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DNOAServer.Models
{

    public class ClientAuthorization
    {
        public string User { get; set; }
        public string Client { get; set; }
        public HashSet<string> Scope { get; set; }
        public string Code { get; set; }
        public DateTime Expires { get; set; }
    }
}