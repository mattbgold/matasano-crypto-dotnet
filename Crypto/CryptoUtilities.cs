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

        public static byte[] AesDecryptECB(byte[] inputBytes, byte[] key)
        {
            var blocks = inputBytes.Chunk(16);
            var decrypted = blocks.SelectMany(block => AES128BlockDecrypt(block.ToArray(), key)).ToArray();

            return decrypted;
        }

        public static byte[] AesEncryptECB(byte[] inputBytes, byte[] key)
        {
            inputBytes = PadToBlockSize(inputBytes, 16);
            
            var blocks = inputBytes.Chunk(16);
            var encryptedBlocks = blocks.Select(block => AES128BlockEncrypt(block.ToArray(), key));
            return encryptedBlocks.SelectMany(x => x).ToArray();
        }

        public static byte[] AESEncryptCBC(byte[] inputBytes, byte[] key, byte[] iv)
        {
            var blocks = inputBytes.Chunk(16).ToArray();
            List<byte[]> encryptedBlocks = new List<byte[]>();
            for (int i = 0; i < blocks.Count(); i++)
            {
                var encryptedBlock = AesEncryptECB(blocks[i].ToArray().XOR(i == 0 ? iv : encryptedBlocks[i - 1].ToArray()), key);
                encryptedBlocks.Add(encryptedBlock);
            }

            return encryptedBlocks.SelectMany(x => x).ToArray();
        }

        public static byte[] AESDecryptCBC(byte[] inputBytes, byte[] key, byte[] iv)
        {
            var blocks = inputBytes.Chunk(16).ToArray();
            List<byte[]> decryptedBlocks = new List<byte[]>();
            for (int i = 0; i < blocks.Count(); i++)
            {
                var decryptedBlock = AesDecryptECB(blocks[i].ToArray(), key).XOR(i == 0 ? iv : blocks[i - 1].ToArray());
                decryptedBlocks.Add(decryptedBlock);
            }

            return decryptedBlocks.SelectMany(x => x).ToArray();
        }

        public static bool AreBytesECBEncrypted(byte[] bytes)
        {
            byte[][] chunks = bytes.Chunk(16).Select(x=>x.ToArray()).ToArray();
            var distinctLength = chunks.Distinct(new BytesComparer()).Count();
            return distinctLength < chunks.Count();
        }

        private static byte[] PadToBlockSize(byte[] bytes, int blockSize)
        {
            var dif = (bytes.Length % blockSize);
            if (dif == 0)
            {
                return bytes;
            }
            else
            {
                return PadBytes(bytes, bytes.Length + blockSize - dif);
            }
        }

        /// <summary>
        /// PKCS7 padding
        /// </summary>
        /// <returns></returns>
        public static byte[] PadBytes(byte[] bytes, int toLength)
        {
            int bytesToPad = toLength - bytes.Length;
            if (bytesToPad < 0)
            {
                throw new InvalidOperationException("Byte length is longer than desired length after padding!");
            }

            var padBlock = Convert.ToByte(bytesToPad);
            byte[] paddedBytes = new byte[toLength];
            for (int i = 0; i < toLength; i++)
            {
                if (i < bytes.Length)
                {
                    paddedBytes[i] = bytes[i];
                }
                else
                {
                    paddedBytes[i] = padBlock;
                }
            }

            return paddedBytes;
        }

        public static byte[] AESEncryptionOracle(byte[] bytes)
        {
            var r = new Random();
            var inputBytes = bytes.ToList();
            inputBytes.AddRange(RandomBytes(r.Next(1, 6)));
            var paddedBytes = RandomBytes(r.Next(1, 6)).ToList();
            paddedBytes.AddRange(inputBytes);
            
            if (r.Next(2) == 0)
            {
                return AesEncryptECB(paddedBytes.ToArray(), RandomBytes(16));
            }
            else
            {
                return AESEncryptCBC(paddedBytes.ToArray(), RandomBytes(16), RandomBytes(16));
            }            
        }

        #region  Private

        private static byte[] RandomBytes(int num)
        {
            var key = new byte[num];
            new Random().NextBytes(key);
            return key;
        }

        private static byte[] AES128BlockEncrypt(byte[] plainText, byte[] Key)
        {
            byte[] output_buffer = new byte[plainText.Length];

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Mode = CipherMode.ECB;

                aesAlg.BlockSize = 128;
                aesAlg.KeySize = 128;
                aesAlg.Padding = PaddingMode.None;
                aesAlg.Key = Key;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                encryptor.TransformBlock(plainText, 0, plainText.Length, output_buffer, 0);
            }

            return output_buffer;
        }

        private static byte[] AES128BlockDecrypt(byte[] cipherText, byte[] Key)
        {
            // Declare the string used to hold the decrypted text. 
            byte[] output_buffer = new byte[cipherText.Length];

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Mode = CipherMode.ECB;

                aesAlg.BlockSize = 128;
                aesAlg.KeySize = 128;
                aesAlg.Padding = PaddingMode.None;
                aesAlg.Key = Key;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                decryptor.TransformBlock(cipherText, 0, cipherText.Length, output_buffer, 0);
            }

            return output_buffer;
        }
        #endregion
    }
}
