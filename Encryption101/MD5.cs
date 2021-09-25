using Encryption101.Tools;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Encryption101
{
    public class MD5101
    {
        /// <summary>
        /// Returns a MD5 hash as a string
        /// </summary>
        /// <param name="text">String to be hashed.</param>
        /// <returns>Hash as string.</returns>
        public static string GetMd5Hash(string text, ByteConversion? conversion = null)
        {
            var textBytes = Encoding.UTF8.GetBytes(text);
            using ( var md5 = new MD5CryptoServiceProvider())
            {
                var hash = md5.ComputeHash(textBytes);
                var result = hash.HashToText(conversion);
                return result;
            }
        }

        public static bool IsValidMD5(string md5)
        {
            if (md5 == null || md5.Length != 32) 
                return false;

            return md5.ToLower().All(x =>    x >= '0' && x <= '9' 
                                          || x >= 'a' && x <= 'f');
        }
    }
}
