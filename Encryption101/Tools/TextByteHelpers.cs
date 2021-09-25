using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encryption101.Tools
{
    internal static class TextByteHelpers
    {
        internal static string EncryptedToText(this byte[] bytes, ByteConversion? conversion)
        {
            return bytes.ToText(conversion ?? EncryptionDefaults.CryptByteConversion);
        }

        internal static string HashToText(this byte[] bytes, ByteConversion? conversion)
        {
            return bytes.ToText(conversion ?? EncryptionDefaults.HashByteConversion);
        }

        internal static byte[] HashToBytes(this string text, ByteConversion? conversion)
        {
            return text.ToBytes(conversion ?? EncryptionDefaults.HashByteConversion);
        }

        internal static byte[] EncryptedToBytes(this string text, ByteConversion? conversion)
        {
            return text.ToBytes(conversion ?? EncryptionDefaults.CryptByteConversion);
        }

        internal static string ToText(this byte[] bytes, ByteConversion conversion)
        {
            string result;
            
            switch( conversion )
            {
                case ByteConversion.HexLowerCase:
                    result = BitConverter.ToString(bytes)
                                .Replace("-", string.Empty)
                                .ToLower();
                    break;
                case ByteConversion.HexUpperCase:
                    result = BitConverter.ToString(bytes)
                                .Replace("-", string.Empty)
                                .ToUpper();
                    break;
                case ByteConversion.Base64:
                    result = Convert.ToBase64String(bytes);
                    break;
                default:
                    result = Convert.ToBase64String(bytes);
                    break;
            }
            return result;
        }

        internal static byte[] ToBytes(this string text, ByteConversion conversion)
        {
            byte[] result;

            switch (conversion)
            {
                case ByteConversion.HexLowerCase:
                case ByteConversion.HexUpperCase:
                    var len = text.Length;
                    result = new byte[len / 2];
                    for (int i = 0; i < len; i += 2)
                        result[i / 2] = Convert.ToByte(text.Substring(i, 2), 16); ;
                    break;
                case ByteConversion.Base64:
                    result = Convert.FromBase64String(text);
                    break;
                default:
                    result = Convert.FromBase64String(text);
                    break;
            }
            return result;
        }
    }
}
