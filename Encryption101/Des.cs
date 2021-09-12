using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encryption101
{
    public class DES101
    {
        private static byte[] CreateKey(string password)
        {
            using (var result = SHA384.Create(password))
            {
                return result.Hash;
            }
        }

        /// <summary>
        /// Encrypt text using DES algorithm.
        /// </summary>
        /// <param name="text"></param>
        /// <param name="password">Password that is used for cgenerating the key and IV for encryption</param>
        /// <returns></returns>
        public static string Encrypt(string text, string password)
        {
            var pText = Encoding.UTF8.GetBytes(text);
            var key = CreateKey(password);

            using (var desCryptoService = new DESCryptoServiceProvider())
            {
                desCryptoService.Key = key;
                desCryptoService.IV = key;

                using (var ms = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(ms, desCryptoService.CreateEncryptor(), CryptoStreamMode.Write);
                    cryptoStream.Write(pText, 0, pText.Length);
                    cryptoStream.Dispose();

                    var buffer = new byte[ms.Length];
                    ms.Position = 0;
                    ms.Read(buffer, 0, buffer.Length);

                    var result = Convert.ToBase64String(buffer);
                    return result;
                }
            }
        }
        /// <summary>
        /// Decrypt a given string using DES algorithm
        /// </summary>
        /// <param name="encryptedText"></param>
        /// <param name="password">Password beeing used for generating symmetric key and IV for decryption.</param>
        /// <returns></returns>
        public static string Decrypt(string encryptedText, string password)
        {
            var encryptedTextByte = Encoding.Default.GetBytes(encryptedText);
            var key = CreateKey(password);

            using (var des = new DESCryptoServiceProvider())
            {
                var decryptor = des.CreateDecryptor(key, key);
                using (var ms = new MemoryStream(encryptedTextByte))
                {
                    using (var csDecrypt = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            var res = srDecrypt.ReadToEnd();
                            return res;
                        }
                    }
                }
            }
        }
    }
}
