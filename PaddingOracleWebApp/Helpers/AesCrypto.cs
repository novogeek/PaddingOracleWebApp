using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Web;

namespace PaddingOracleWebApp.Helpers
{
    public static class AESCrypto
    {
        private static byte[] key = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        //public AES_CBCOracle ()
        //{
        //	key = new byte[16]; // { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        //	Random r = new Random ();
        //	r.NextBytes (key);
        //}


        /// <returns>
        /// True if after decryption the PKCS #7 padding is correct, false otherwise.
        /// </returns>
        /// <param name='cipher'>
        /// A 32 bytes block (2 AES blocks) in which the first block is IV,
        /// the second is the encrypted data itself.
        /// </param>
        public static bool Decrypt(byte[] cipher)
        {
            if (cipher.Length != 32)
                throw new Exception("Can decrypt only IV + 1 BLOCK at a time (32 bytes)");

            byte[] cipherIV = new byte[16];
            byte[] cipherData = new byte[cipher.Length - 16];

            //Separate IV and data
            Array.Copy(cipher, cipherIV, 16);
            Array.Copy(cipher, 16, cipherData, 0, cipher.Length - 16);

            byte[] decrypted = AES_DecryptBlock(cipherData, key);
            decrypted = CryptoHelper.Xor(decrypted, cipherIV);

            byte last = decrypted[decrypted.Length - 1];
            if (last == 0 || last > 16)
                return false;

            for (int i = 0; i < last; i++)
            {
                if (decrypted[decrypted.Length - i - 1] != last)
                    return false;
            }

            return true;
        }


        //Decrypts the 16 bytes block @cipherText using @key in ECB mode
        public static byte[] AES_DecryptBlock(byte[] cipherText, byte[] key)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length != 16)
                throw new ArgumentException("cipherText must be a 16 byte array");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");

            // Declare the string used to hold the decrypted text. 
            byte[] output_buffer = new byte[cipherText.Length];

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Mode = CipherMode.ECB;

                aesAlg.BlockSize = 128;
                aesAlg.KeySize = 128;
                aesAlg.Padding = PaddingMode.None;
                aesAlg.Key = key;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                decryptor.TransformBlock(cipherText, 0, cipherText.Length, output_buffer, 0);
            }

            return output_buffer;
        }

        //Encrypts the 16 bytes block @plainText using @key in ECB mode
        public static byte[] AES_EncryptBlock(byte[] plainText, byte[] key)
        {
            byte[] output_buffer = new byte[plainText.Length];

            using (AesManaged aesAlg = new AesManaged())
            {
                //If CBC, must initialize IV = O_{128}
                //aesAlg.Mode = CipherMode.CBC;
                //aesAlg.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                aesAlg.Mode = CipherMode.ECB;

                aesAlg.BlockSize = 128;
                aesAlg.KeySize = 128;
                aesAlg.Padding = PaddingMode.None;
                aesAlg.Key = key;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                encryptor.TransformBlock(plainText, 0, plainText.Length, output_buffer, 0);
            }

            return output_buffer;
        }


        //Decrypts the cipher @cipherText as a string
        public static string AES_DecryptToString(byte[] cipherText)
        {
            if (cipherText == null || cipherText.Length < 16)
                throw new ArgumentException("cipherText must contain at least 16 bytes");
            if (key == null || key.Length <= 0)
                throw new ArgumentException("Key");

            string plaintext = null;

            //First 16 bytes in @cipherText are the IV
            byte[] IV = new byte[16];
            Array.Copy(cipherText, 0, IV, 0, IV.Length);

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.BlockSize = 128;
                aesAlg.Key = key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption. 
                MemoryStream msDecrypt = new MemoryStream(cipherText, 16, cipherText.Length - 16);
                {
                    CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                    {
                        StreamReader srDecrypt = new StreamReader(csDecrypt);
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        //AES Encrypt the string @plainText using the Oracle's key with PKCS#7 padding in CBC mode
        public static byte[] AES_EncryptString(string plainText)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentException("Key");

            byte[] IV = new byte[16];
            Random r = new Random();
            r.NextBytes(IV);

            byte[] encrypted;

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.BlockSize = 128;
                aesAlg.Key = key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption. 
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            byte[] result = new byte[encrypted.Length + IV.Length];

            Array.Copy(IV, result, IV.Length);
            Array.Copy(encrypted, 0, result, IV.Length, encrypted.Length);

            // Return the encrypted bytes from the memory stream. 
            return result;
        }

    }
}