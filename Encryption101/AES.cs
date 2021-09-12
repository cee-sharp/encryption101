using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encryption101
{
    public class AES101
    {
        private static byte[] CreateKey(string password)
        {
            using (var result = SHA384Managed.Create(password))
            {
                return result.Hash;
            }
        }

        /// <summary>
        /// Encrypt text using AES.
        /// </summary>
        /// <param name="text">The text that you want to encrypt</param>
        /// <param name="password">Password to be used for generating the key and IV for AES algorithm</param>
        /// <returns>Encrypted, base64  encoded string</returns>
        public static string EncryptString(string plainText, string password)
        {
            var bytes = Encoding.UTF8.GetBytes(plainText); // parse text to bites array
            using (var aesCryptoService = new AesCryptoServiceProvider())
            { 
                var key = CreateKey(password);
                aesCryptoService.Key = key;
                aesCryptoService.IV = key;

                using (var ms = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(ms, aesCryptoService.CreateEncryptor(), CryptoStreamMode.Write); // open cryptoStream
                    cryptoStream.Write(bytes, 0, bytes.Length);
                    var buffer = new byte[ms.Length];
                    ms.Position = 0;
                    ms.Read(buffer, 0, buffer.Length);
                    cryptoStream.Dispose();

                    return Convert.ToBase64String(buffer);
                }
            }
        }

        /// <summary>
        /// Decrypt text using AES.
        /// </summary>
        /// <param name="text">The encrypted, base64 encoded input string</param>
        /// <param name="password">Password to be used for generating the key and IV for AES algorithm</param>
        /// <returns>Decrypted string</returns>
        public static string DecryptString(string text, string password)
        {
            var encryptedTextByte = Convert.FromBase64String(text);
            var key = CreateKey(password);

            using (var aes = new AesCryptoServiceProvider())
            {
                var decryptor = aes.CreateDecryptor(key, key);
                
                using (var ms = new MemoryStream(encryptedTextByte))
                {
                    using (var csDecrypt = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            var res = srDecrypt.ReadToEnd();
                            csDecrypt.Close();
                            srDecrypt.Close();
                            return res;
                        }
                    }
                }
            }
        }
    }
}
