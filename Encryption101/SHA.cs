using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Encryption101
{
    public class SHA101
    {
        public static string ComputeSHA1Hash(string stringToHash)
        {
            var bytes = Encoding.UTF8.GetBytes(stringToHash);
            using (var sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(bytes);
                var result = BitConverter.ToString(hash)
                                .Replace("-", string.Empty)
                                .ToLower();

                return result;
            }
        }
        public static string ComputeSHA256Hash(string stringToHash)
        {
            var bytes = Encoding.UTF8.GetBytes(stringToHash);

            using (var sha256 = SHA256Managed.Create())
            {
                var hash = sha256.ComputeHash(bytes);
                var result = BitConverter.ToString(hash)
                                .Replace("-", string.Empty)
                                .ToLower();
                return result;
            }
        }
    }
}
