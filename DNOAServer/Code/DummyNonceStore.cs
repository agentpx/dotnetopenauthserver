using DotNetOpenAuth.Messaging.Bindings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace DNOAServer.Code
{
    public class DummyNonceStore : INonceStore
    {
        public bool StoreNonce(string context, string nonce, DateTime timestampUtc)
        {
            return true;
        }
    }
}