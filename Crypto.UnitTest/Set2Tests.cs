using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto.UnitTest
{
    /// <summary>
    /// Crypto Challenge Set 2
    /// http://cryptopals.com/sets/2/
    /// </summary>
    [TestFixture]
    public class Set2Tests
    {
        /// <summary>
        /// Implement PKCS#7 padding
        /// http://cryptopals.com/sets/2/challenges/9/
        /// </summary>
        /// <param name="bytesToPad">key input</param>
        /// <param name="desiredLength">how many bytes we need total, after padding</param>
        /// <returns>bytes padded with PKCS7</returns>
        [TestCase("YELLOW SUBMARINE", 20, Result=new byte[]{89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4})]
        public byte[] Challenge9(string bytesToPad, int desiredLength)
        {
            return CryptoUtilities.PadBytes(bytesToPad.ToBytes(), desiredLength);
        }
    }
}
