﻿using System;
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
            return ToBytes(str, null);
        }
        public static byte[] ToBytes(this String str, int? @base)
        {
            if (@base.HasValue) //This indicates the string is a *special* representation of bytes such as Hex or Base64
            {
                return Enumerable.Range(0, str.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(str.Substring(x, 2), @base.Value)).ToArray();
            }
            else //we just want the byte representation of the string itself.
            {
                return System.Text.Encoding.ASCII.GetBytes(str);
            }
        }

        public static byte[] XOR(this Byte[] self, IList<byte> key)
        {
            //Damn skippy, this xors a byte array with another byte array "key", repeating the key if needed.
            return Enumerable.Range(0, self.Length).Select(i => (byte)(self[i] ^ key[i % key.Count()])).ToArray();
        }

        public static string ToHexString(this Byte[] self)
        {
            return BitConverter.ToString(self).Replace("-", "").ToLower();
        }
    } 
}
