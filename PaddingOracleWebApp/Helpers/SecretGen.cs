using System;
using System.Security.Cryptography;

namespace PaddingOracleWebApp.Helpers
{
    public static class SecretGen
    {
        private static byte[] secretkey = new Byte[64];
        public static byte[] GetSecret()
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(secretkey);
            }
            return secretkey;
        }
    }
}