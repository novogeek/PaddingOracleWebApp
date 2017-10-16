using System;
using System.Text;
using System.Web;
using System.Security.Cryptography;

namespace PaddingOracleWebApp.Helpers
{
    public static class TamperProofQueryString
    {
        private static byte[] secretkey = SecretGen.GetSecret();
        public static string GetTamperProofToken(string queryString)
        {
            return ComputeHash(queryString);
        }

        private static string ComputeHash(string data)
        {
            // Get bytes from plaintext
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(data);

            // Initialize HMAC SHA512 Algorithm with secret key
            HMACSHA512 hashAlg = new HMACSHA512(secretkey);

            // Compute Keyed Hash
            byte[] keyHashBytes = hashAlg.ComputeHash(plainTextBytes);

            // Convert Keyed Hash to Hex string and replace the hyphens in the result.
            string keyHash = BitConverter.ToString(keyHashBytes).Replace("-", "");
            return keyHash;
        }

        public static bool ValidateQueryString(string cipherText, string hmac, out string msg)
        {
            bool isValid = false;
            msg = string.Empty;
            
            if (string.IsNullOrEmpty(cipherText))
            {
                msg = "Tampering detected! Cipher text is expected but was not sent";
                isValid = false;
                return isValid;
            }
            if (string.IsNullOrEmpty(hmac))
            {
                msg = "Tampering detected! HMAC token is expected but was not sent!";
                isValid = false;
                return isValid;
            }
            //If the hash that was sent on the querystring does not match our compute of that hash given the 
            // current data in the querystring, then throw an exception
            if (ComputeHash(cipherText) == hmac) {
                isValid = true;
                return isValid;
            }
            else{
                //throw new ApplicationException("Querystring hash values don't match");
                msg = "Tampering detected! Integrity check failed!";
                isValid = false;
                return isValid;
            }
        }

        /*public static bool ValidateQueryString(out string msg)
        {
            bool isValid = true;
            msg = string.Empty;
            HttpRequest request = HttpContext.Current.Request;
            if (request.QueryString.Count == 0)
            {
                msg = "Query string is expected but was not sent";
                isValid = false;
                return isValid;
            }
            //Get the entire querystring (minus initial ?)
            string queryString = request.Url.Query.TrimStart(new char[] { '?' });

            //Get just our hash value from the querystring collection, if none present throw exception
            string submittedHash = request.QueryString["HMacToken"];
            if (submittedHash == null)
            {
                //throw new ApplicationException("Querystring validation hash was not sent!");
                msg = "Querystring validation hash was not sent!";
                isValid = false;
                return isValid;
            }

            //Take the original querystring and get all of it except our hash (we need to recompute the hash
            // just like it was done on the original querystring)
            int hashPos = queryString.IndexOf("&HMacToken=");
            queryString = queryString.Substring(0, hashPos);

            //If the hash that was sent on the querystring does not match our compute of that hash given the 
            // current data in the querystring, then throw an exception
            if (ComputeHash(queryString) != submittedHash)
            {
                //throw new ApplicationException("Querystring hash values don't match");
                msg = "Querystring hash values don't match";
                isValid = false;
                return isValid;
            }
            return isValid;
        }*/
    }
}