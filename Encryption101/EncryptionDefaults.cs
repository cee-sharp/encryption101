using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption101
{
    public static class EncryptionDefaults
    {
        /// <summary>
        /// Used as a default setting when converting bytes to text and vice versa
        /// in encryption functions. The default value is "Base64".
        /// </summary>
        public static ByteConversion CryptByteConversion { get; set; } = ByteConversion.Base64;

        /// <summary>
        /// Used as a default setting when converting bytes to text and vice versa
        /// in hash functions. The default value is "Hex".
        /// </summary>
        public static ByteConversion HashByteConversion { get; set; } = ByteConversion.HexLowerCase;
    }


}
