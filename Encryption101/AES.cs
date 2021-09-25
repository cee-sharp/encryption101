using Encryption101.Tools;
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
            using (var result = SHA256Managed.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(password);
                result.ComputeHash(bytes);
                return result.Hash ;
            }
        }

        private static byte[] CopyHalf(byte[] input)
        {
            var result = new byte[input.Length / 2];
            Array.Copy(input, 0, result, 0, input.Length / 2);
            return result;
        }

        /// <summary>
        /// Encrypt text using AES.
        /// </summary>
        /// <param name="text">The text that you want to encrypt</param>
        /// <param name="password">Password to be used for generating the key and IV for AES algorithm</param>
        /// <returns>Encrypted, base64  encoded string</returns>
        public static string EncryptString(string plainText, string password, ByteConversion? conversion = null)
        {
            var bytes = Encoding.UTF8.GetBytes(plainText); // parse text to byte array
            using (var aes = new AesManaged())
            { 
                var key = CreateKey(password);
                aes.Key = key;
                aes.IV = CopyHalf(key);

                using (var ms = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write); // open cryptoStream
                    cryptoStream.Write(bytes, 0, bytes.Length);
                    cryptoStream.FlushFinalBlock();
                    var buffer = new byte[ms.Length];
                    ms.Position = 0;
                    ms.Read(buffer, 0, buffer.Length);
                    cryptoStream.Dispose();

                    return buffer.EncryptedToText(conversion);
                }
            }
        }

        /// <summary>
        /// Decrypt text using AES.
        /// </summary>
        /// <param name="text">The encrypted, base64 encoded input string</param>
        /// <param name="password">Password to be used for generating the key and IV for AES algorithm</param>
        /// <returns>Decrypted string</returns>
        public static string DecryptString(string text, string password, ByteConversion? conversion = null)
        {
            var encryptedTextByte = text.EncryptedToBytes(conversion);
            var key = CreateKey(password);

            using (var aes = new AesCryptoServiceProvider())
            {
                var decryptor = aes.CreateDecryptor(key, CopyHalf(key));
                
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
