using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using System.IO;
using System.Security.Cryptography;

namespace Crypto.Challenges.Test
{
    /// <summary>
    /// Crypto Challenge Set 1
    /// http://cryptopals.com/sets/1/
    /// </summary>
    [TestFixture]
    public class Set1Tests
    {
        /// <summary>
        /// Convert hex to base64
        /// http://cryptopals.com/sets/1/challenges/1/
        /// </summary>
        /// <param name="input">hexaxdecimal string</param>
        /// <returns>base64 representation of the hexadecimal input</returns>
        [TestCase("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d", 
            Result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")]
        public string Challenge1(string input)
        {
            return Convert.ToBase64String(input.ToBytes(16));
        }


        /// <summary>
        /// Fixed XOR
        /// http://cryptopals.com/sets/1/challenges/2/
        /// </summary>
        /// <param name="input1">hex string</param>
        /// <param name="input2">another hex string</param>
        /// <returns>hex representation of the two inputs XOR'd against one another</returns>
        [TestCase("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965",
            Result="746865206b696420646f6e277420706c6179")]
        public string Challenge2(string input1, string input2)
        {
            return input1.ToBytes(16).XOR(input2.ToBytes(16)).ToHexString();
        }


        /// <summary>
        /// Single-byte XOR cipher
        /// http://cryptopals.com/sets/1/challenges/3/
        /// </summary>
        /// <param name="input">hex encoded string that has been XOR'd against a single character</param>
        /// <returns>Decrypted answer with the highest english text score</returns>
        [TestCase("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", 
            Result = "Cooking MC's like a pound of bacon")]
        public string Challenge3(string input)
        {
            var candidates = new List<string>();
            for (var i = 0x00; i <= 0x7F; i++)
            {
                var byteArray = input.ToBytes(16).XOR(new byte[]{(byte)i});
                candidates.Add(System.Text.Encoding.ASCII.GetString(byteArray));
            }
            var result = TextAnalysis.GetHighestScore(candidates);
            Console.WriteLine(result);

            return result;
        }


        /// <summary>
        /// Detect single-character XOR
        /// http://cryptopals.com/sets/1/challenges/4/
        /// </summary>
        /// <returns>Decrypted answer with the highest english text score</returns>
        [TestCase(Result="Now that the party is jumping")]
        public string Challenge4()
        {
            string[] lines = File.ReadAllLines(@"Files\4.txt", Encoding.ASCII);
            var highestScore = -1000;
            var highestStr = "";

            foreach (var line in lines)
            {
                var encryptedBytes = line.ToBytes(16);

                for (var i = 0x00; i <= 0x7F; i++)
                {
                    var byteArray = encryptedBytes.XOR(new byte[]{(byte)i});
                    var decodedString = System.Text.Encoding.ASCII.GetString(byteArray);
                    var score = TextAnalysis.GetScore(decodedString);
                    if (score > highestScore)
                    {
                        highestScore = score;
                        highestStr = decodedString;
                    }
                }
            }
            
            Console.WriteLine(highestStr);
            return highestStr.Replace("\n", "");
        }


        /// <summary>
        /// Implement repeating-key XOR
        /// http://cryptopals.com/sets/1/challenges/5/
        /// </summary>
        /// <param name="key"></param>
        /// <param name="bytesToEncrypt"></param>
        /// <returns></returns>
        [TestCase("ICE", "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
            Result="0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")]
        public string Challenge5(string key, string bytesToEncrypt)
        {
            return bytesToEncrypt.ToBytes().XOR(key.ToBytes()).ToHexString();
        }


        /// <summary>
        /// Break repeating-key XOR
        /// http://cryptopals.com/sets/1/challenges/6/
        /// </summary>
        [Test]
        public void Challenge6()
        {
            Assert.That(CryptoUtilities.GetHammingDistance("this is a test", "wokka wokka!!!") == 37);

            string fileTextBase64 =  File.ReadAllText(@"Files\6.txt", Encoding.ASCII);
            string fileTextASCII = Encoding.ASCII.GetString(Convert.FromBase64String(fileTextBase64));

            int keySize = CryptoUtilities.GetPotentialXorKeySizes(fileTextASCII, 2, 40, 1).First();
            Console.WriteLine(String.Format("Key Size is: {0}", keySize));

            byte[] key = CryptoUtilities.ExtractRepeatingKeyXOR(fileTextASCII, keySize);

            Console.WriteLine("Key: " + Encoding.ASCII.GetString(key));

            var solution = Encoding.ASCII.GetString(fileTextASCII.ToBytes().XOR(key));
            Console.WriteLine(solution);

            string fileSolution = File.ReadAllText(@"Files\6_Solution.txt").Replace("\r\n", "\n");
            Assert.That(solution.CompareTo(fileSolution) == 0);
        }


        /// <summary>
        /// AES in ECB mode
        /// http://cryptopals.com/sets/1/challenges/7/
        /// </summary>
        /// <param name="key"></param>
        [TestCase("YELLOW SUBMARINE")]
        public void Challenge7(string key)
        {
            var fileBytes = Convert.FromBase64String(File.ReadAllText(@"Files\7.txt"));
            var solution = CryptoUtilities.AesDecryptECB(fileBytes, key.ToBytes());
            Console.WriteLine(solution);
            
            //string fileSolution = File.ReadAllText(@"Files\7_Solution.txt").Replace("\r\n", "\n");
            Assert.That(solution.StartsWith("I'm back and"));
        }

        [TestCase]
        public void Challenge8()
        {
            var lines = File.ReadAllLines(@"Files\8.txt").Select(x=>x.ToBytes(16));

            Assert.DoesNotThrow(()=>Encoding.ASCII.GetString(lines.Single(x => CryptoUtilities.AreBytesECBEncrypted(x))));

            /*foreach (var bytes in lines)
            {
                if (CryptoUtilities.AreBytesECBEncrypted(bytes))
                {
                    Console.WriteLine(Encoding.ASCII.GetString(bytes));
                }
            }*/
        }
    }
}
