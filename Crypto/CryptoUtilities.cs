using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("Crypto.Challenges.Tests")]
namespace Crypto
{
    public static class CryptoUtilities
    {
        public static int[] GetPotentialXorKeySizes(string encryptedText, int minKeySize, int maxKeySize, int howMany)
        {
            Dictionary<int, float> keySizes = new Dictionary<int, float>();
            for (int tryKeySize = minKeySize; tryKeySize <= maxKeySize; tryKeySize++)
            {
                List<float> distances = new List<float>();

                for (int j = 0; j < (encryptedText.Length - tryKeySize*2); j += tryKeySize*2)
                {
                    var sub1 = encryptedText.Substring(j, tryKeySize);
                    var sub2 = encryptedText.Substring(j + tryKeySize, tryKeySize);
                    distances.Add((float)GetHammingDistance(sub1, sub2) / (float)tryKeySize);
                }

                var avg = distances.Average();

                keySizes.Add(tryKeySize, avg);
            }

            return keySizes.OrderBy(x => x.Value).Select(x => x.Key).Take(howMany).ToArray();
        }

        public static int GetHammingDistance(string a, string b)
        {
            if (a.Length != b.Length)
            {
                throw new ArgumentException("Byte arrays must be of equal length");
            }

            BitArray aBits = new BitArray(a.ToBytes());
            BitArray bBits = new BitArray(b.ToBytes());

            return Enumerable.Range(0, aBits.Length).Count(i => aBits[i] != bBits[i]);
        }

        /// <summary>
        /// Break a list of items into chunks of a specific size
        /// </summary>
        public static IEnumerable<IEnumerable<T>> Chunk<T>(this IEnumerable<T> source, int chunksize)
        {
            while (source.Any())
            {
                yield return source.Take(chunksize);
                source = source.Skip(chunksize);
            }
        }

        /// <summary>
        /// Given an encrypted string and a keysize, finds the key.
        /// This assumes the key starts on the first character of the file. 
        /// </summary>
        /// <param name="file"></param>
        /// <param name="keySize"></param>
        /// <returns></returns>
        public static byte[] ExtractRepeatingKeyXOR(string file, int keySize)
        {
            var bytes = file.ToBytes();
            var blocks = CryptoUtilities.Chunk<byte>(bytes, keySize);
            byte[][] transposed = blocks.Transpose().Select(x => x.ToArray()).ToArray();

            return transposed.Select(x => FindSingleKeyXORdWithString(x)).ToArray();
        }

        /// <summary>
        /// Finds the byte that, when XOR'd with the input string, produces the most englishey (decrypted) text
        /// </summary>
        /// <param name="encodedStringBytes">an encrypted string</param>
        /// <returns>the byte key</returns>
        public static byte FindSingleKeyXORdWithString(byte[] encodedStringBytes)
        {
            var highestScore = int.MinValue;
            var highestByte = 0x00;
            for (var i = 0x00; i <= 0x7F; i++)
            {
                var byteArray = encodedStringBytes.XOR(new byte[] { (byte)i });
                var decodedString = System.Text.Encoding.ASCII.GetString(byteArray);
                var score = TextAnalysis.GetScore(decodedString);
                if (score > highestScore)
                {
                    highestScore = score;
                    highestByte = i;
                }
            }
            return (byte)highestByte;
        }

        public static string AesDecryptECB(byte[] inputBytes, byte[] key)
        {
            Byte[] outputBytes = inputBytes;

            string plaintext = string.Empty;

            using (MemoryStream memoryStream = new MemoryStream(outputBytes))
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, GetCryptoAlgorithm(key).CreateDecryptor(key, key), CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(cryptoStream))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }

            return plaintext;
        }

        public static bool AreBytesECBEncrypted(byte[] bytes)
        {
            var chunks = bytes.Chunk(16);
            var distinctLength = chunks.Distinct(new BytesComparer()).Count();
            return distinctLength < chunks.Count();
        }

        private static AesManaged GetCryptoAlgorithm(byte[] key)
        {
            //set the mode, padding and block size
            var algorithm = new AesManaged();
            algorithm.Padding = PaddingMode.None;
            algorithm.Mode = CipherMode.ECB;
            algorithm.KeySize = key.Length*8;
            algorithm.BlockSize = 128;
            return algorithm;
        }
    }
}
