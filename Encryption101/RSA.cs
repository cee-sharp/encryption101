using Encryption101.Tools;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Encryption101
{
    public class RSA101
    {
        public static RSAKeysModel GenerateKeys(int keySize)
        {
            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                var model = new RSAKeysModel
                {
                    PrivateKey = rsa.ToXmlString(true),
                    PublicKey = rsa.ToXmlString(false)
                };
                return model;
            }

        }

        /// <summary>
        /// Encrypt data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] data, string publicKey)
        {
            using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
            {
                rsaCryptoServiceProvider.FromXmlString(publicKey);
                var encryptedData = rsaCryptoServiceProvider.Encrypt(data, false);
                return encryptedData;
            }
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string Encrypt(string data, string publicKey, ByteConversion? conversion = null)
        {
            var dataArray = Encoding.UTF8.GetBytes(data);
            var bytes = Encrypt(dataArray, publicKey);
            var res = bytes.EncryptedToText(conversion);
            return res;
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <returns>Base64 string result</returns>
        public static byte[] Decrypt(byte[] data, string privateKey)
        {
            using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
            {
                rsaCryptoServiceProvider.FromXmlString(privateKey);
                var decryptedData = rsaCryptoServiceProvider.Decrypt(data, false);
                return decryptedData;
            }
        }

        /// <summary>
        /// Decrypt a string with RSA
        /// </summary>
        /// <param name="data">the encrypted data</param>
        /// <param name="privateKey">your password</param>
        /// <param name="conversion">optional byte conversion method</param>
        /// <returns></returns>
        public static string Decrypt(string data, string privateKey, ByteConversion? conversion = null)
        {
            var dataArray = data.EncryptedToBytes(conversion);
            var res = Encoding.UTF8.GetString(Decrypt(dataArray, privateKey));
            return res;
        }

        public static string SignData(string message, string privateKey, ByteConversion? conversion = null)
        {
            //// The array to store the signed message in bytes
            byte[] signedBytes;
            using (var rsa = new RSACryptoServiceProvider())
            {
                var originalData = Encoding.UTF8.GetBytes(message);

                try
                {
                    rsa.FromXmlString(privateKey);
                    // Sign the data, using SHA512 as the hashing algorithm
                    signedBytes = rsa.SignData(originalData, CryptoConfig.MapNameToOID("SHA512"));
                }
                catch (CryptographicException e)
                {
                    Console.WriteLine(e.Message);
                    return null;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
            //// Convert the a base64 string before returning
            return signedBytes.EncryptedToText(conversion);
        }

        /// <summary>
        /// verify a signed string on behalf of a public key
        /// </summary>
        /// <param name="originalMessage">The text</param>
        /// <param name="signedMessage">signed version of that text</param>
        /// <param name="publicKey">public key used for signing</param>
        /// <param name="conversion">optinal to enforce a specific byte conversion</param>
        /// <returns></returns>
        public static bool VerifyData(string originalMessage, string signedMessage, string publicKey, ByteConversion? conversion = null)
        {

            using (var rsa = new RSACryptoServiceProvider())
            {
                var bytesToVerify = Encoding.UTF8.GetBytes(originalMessage);
                var signedBytes = signedMessage.EncryptedToBytes(conversion);
                rsa.FromXmlString(publicKey);
                return rsa.VerifyData(bytesToVerify, CryptoConfig.MapNameToOID("SHA512"), signedBytes);
            }
        }

    }

    public class RSAKeysModel
    {
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
    }

}
