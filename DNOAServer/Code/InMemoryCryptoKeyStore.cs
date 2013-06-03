using DotNetOpenAuth.Messaging.Bindings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Collections;
using System.Runtime.CompilerServices;

namespace DNOAServer.Code
{
    public class InMemoryCryptoKeyStore : ICryptoKeyStore
    {

        private static List<CryptoKeyStoreEntry> keys = new List<CryptoKeyStoreEntry>();

        [MethodImpl(MethodImplOptions.Synchronized)]
        public CryptoKey GetKey(string bucket, string handle)
        {
            return keys.Where(k => k.Bucket == bucket && k.Handle == handle)
                                                                            .Select(k => k.Key)
                                                                            .FirstOrDefault();
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public IEnumerable<KeyValuePair<string, CryptoKey>> GetKeys(string bucket)
        {
            return keys.Where(k => k.Bucket == bucket).OrderByDescending(k=>k.Key.ExpiresUtc)
                                                        .Select(k=> new KeyValuePair<string,CryptoKey>(k.Handle,k.Key));
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public void RemoveKey(string bucket, string handle)
        {
            keys.RemoveAll(k => k.Bucket == bucket && k.Handle == handle);
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public void StoreKey(string bucket, string handle, CryptoKey key)
        {

            var entry = new CryptoKeyStoreEntry();
            entry.Bucket = bucket;
            entry.Handle = handle;
            entry.Key = key;
            keys.Add(entry);
        }
    }
}