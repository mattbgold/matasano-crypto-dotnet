using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("Crypto.Challenges.Tests")]
namespace Crypto
{
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
    }
}
