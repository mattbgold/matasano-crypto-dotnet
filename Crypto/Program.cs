using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Crypto
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Crypto Challenge #6:");
            //Console.WriteLine(CryptoUtilities.GetHammingDistance("this is a test".ToBytes(), "wokka wokka!!!".ToBytes()));

            string fileText = File.ReadAllText(@"Files\6.txt", Encoding.ASCII);

            int keySize = CryptoUtilities.FindKeySize(fileText, 2, 40);
            
            Console.WriteLine(keySize);
            Console.ReadLine();
        }
    }

    public static class CryptoUtilities
    {
        public static int FindKeySize(string encryptedText, int minKeySize, int maxKeySize)
        {
            
                float shortestDistance = 1000f;
                int keySize = 0;
                for (int tryKeySize = minKeySize; tryKeySize <= maxKeySize; tryKeySize++)
                {
                    List<float> distances = new List<float>();
                    //for (int k = 1; k < 10; k += 1)
                    //{
                        for (int j = 0; j < 100; j += 5)
                        {
                            var sub1 = encryptedText.Substring(j, tryKeySize);
                            var sub2 = encryptedText.Substring(j + tryKeySize, tryKeySize);
                            distances.Add((float)GetHammingDistance(sub1, sub2) / (float)tryKeySize);
                        }
                    //}
                    var avg = distances.Average();
                    if(avg < 3)
                        Console.WriteLine(tryKeySize + ": " + avg);
                    if (avg < shortestDistance)
                    {
                        shortestDistance = avg;
                        keySize = tryKeySize;
                    }
                }
            

            return keySize;
        }

        private static int GetHammingDistance(string a, string b)
        {
            if (a.Length != b.Length)
            {
                throw new ArgumentException("Byte arrays must be of equal length");
            }

            BitArray aBits = new BitArray(a.ToBytes());
            BitArray bBits = new BitArray(b.ToBytes());

            return Enumerable.Range(0, aBits.Length).Count(i => aBits[i] != bBits[i]);
        }
    }
}
