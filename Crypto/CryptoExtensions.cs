using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto
{
    public static class CryptoExtensions
    {
        public static byte[] ToBytes(this String str)
        {
            return ToBytes(str, ByteString.UTF8);
        }
        /// <summary></summary>
        /// <param name="str"></param>
        /// <param name="base">2, 8, 10, 16, or 64</param>
        /// <returns></returns>
        public static byte[] ToBytes(this String str, ByteString encoding)
        {
            switch (encoding)
            {
                case ByteString.Binary:
                    return GetBytesFromEncodedString(str, 2);
                case ByteString.Octal:
                    return GetBytesFromEncodedString(str, 8);
                case ByteString.Hexadecimal:
                    return GetBytesFromEncodedString(str, 16);
                case ByteString.Base64:
                    return Convert.FromBase64String(str);
                default : return System.Text.Encoding.ASCII.GetBytes(str);
            }
        }

        public static string ToAscii(this Byte[] bytes)
        {
            return ToString(bytes, ByteString.UTF8);
        }

        public static string ToString(this Byte[] bytes, ByteString encoding)
        {
            switch (encoding)
            {
                case ByteString.Binary:
                case ByteString.Octal:
                    throw new NotImplementedException();
                case ByteString.Hexadecimal:
                    return BitConverter.ToString(bytes).Replace("-", "").ToLower();
                case ByteString.Base64:
                    return Convert.ToBase64String(bytes);
                default: return System.Text.Encoding.ASCII.GetString(bytes);
            }
        }

        private static byte[] GetBytesFromEncodedString(string str, int @base)
        {
            return Enumerable.Range(0, str.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(str.Substring(x, 2), @base)).ToArray();
        }

        public static byte[] XOR(this Byte[] self, IList<byte> key)
        {
            //Damn skippy, this xors a byte array with another byte array "key", repeating the key if needed.
            return Enumerable.Range(0, self.Length).Select(i => (byte)(self[i] ^ key[i % key.Count()])).ToArray();
        }

        /// <summary>
        /// Swaps the rows and columns of a nested sequence.
        /// </summary>
        public static IEnumerable<IEnumerable<T>> Transpose<T>(
                 this IEnumerable<IEnumerable<T>> source)
        {
            return from row in source
                   from col in row.Select(
                       (x, i) => new KeyValuePair<int, T>(i, x))
                   group col.Value by col.Key into c
                   select c as IEnumerable<T>;
        }
    } 
}
