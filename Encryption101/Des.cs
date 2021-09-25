using Encryption101.Tools;
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
            using (var result = MD5.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(password);
                result.ComputeHash(bytes);
                return result.Hash;
            }
        }

        private static byte[] CopyHalf(byte[] input)
        {
            var result = new byte[input.Length / 2];
            Array.Copy(input, 0, result, 0, input.Length / 2);
            return result;
        }

        /// <summary>
        /// Encrypt text using DES algorithm.
        /// </summary>
        /// <param name="text"></param>
        /// <param name="password">Password that is used for cgenerating the key and IV for encryption</param>
        /// <returns></returns>
        public static string Encrypt(string text, string password, ByteConversion? conversion = null)
        {
            var pText = Encoding.UTF8.GetBytes(text);
            var key = CopyHalf(CreateKey(password));

            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = key;
                des.IV = key;

                using (var ms = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
                    cryptoStream.Write(pText, 0, pText.Length);
                    cryptoStream.FlushFinalBlock();

                    var buffer = new byte[ms.Length];
                    ms.Position = 0;
                    ms.Read(buffer, 0, buffer.Length);

                    var result = buffer.EncryptedToText(conversion);
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
        public static string Decrypt(string encryptedText, string password, ByteConversion? conversion = null)
        {
            var dataBytes = encryptedText.EncryptedToBytes(conversion);
            var key = CopyHalf(CreateKey(password));

            using (var des = new DESCryptoServiceProvider())
            {
                var decryptor = des.CreateDecryptor(key, key);
                using (var ms = new MemoryStream(dataBytes))
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
