using Encryption101.Tools;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Encryption101
{
    public class SHA101
    {
        /// <summary>
        /// Compute a SHA1 hash for a given string.
        /// </summary>
        /// <param name="stringToHash">input value for computation</param>
        /// <param name="conversion">optional to format output</param>
        /// <returns></returns>
        public static string ComputeSHA1Hash(string stringToHash, ByteConversion? conversion = null)
        {
            var bytes = Encoding.UTF8.GetBytes(stringToHash);
            using (var sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(bytes);
                var result = hash.HashToText(conversion);

                return result;
            }
        }

        /// <summary>
        /// Compute a SHA256 hash for a given string.
        /// </summary>
        /// <param name="stringToHash">input value for computation</param>
        /// <param name="conversion">optional to format output</param>
        /// <returns></returns>
        public static string ComputeSHA256Hash(string stringToHash, ByteConversion? conversion = null)
        {
            var bytes = Encoding.UTF8.GetBytes(stringToHash);

            using (var sha256 = SHA256Managed.Create())
            {
                var hash = sha256.ComputeHash(bytes);
                var result = hash.HashToText(conversion);
                return result;
            }
        }

        /// <summary>
        /// Compute a SHA384 hash for a given string.
        /// </summary>
        /// <param name="stringToHash">input value for computation</param>
        /// <param name="conversion">optional to format output</param>
        /// <returns></returns>
        public static string ComputeSHA384Hash(string stringToHash, ByteConversion? conversion = null)
        {
            var bytes = Encoding.UTF8.GetBytes(stringToHash);

            using (var sha = SHA384Managed.Create())
            {
                var hash = sha.ComputeHash(bytes);
                var result = hash.HashToText(conversion);
                return result;
            }
        }
    }
}
