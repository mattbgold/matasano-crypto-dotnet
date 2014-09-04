using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto
{
    class BytesComparer : IEqualityComparer<byte[]>
    {

        public bool Equals(byte[] x, byte[] y)
        {
            return ArraysEqual(x, y);
        }

        public int GetHashCode(byte[] obj)
        {
            return obj.Length;
        }

        private bool ArraysEqual(byte[] a1, byte[] a2)
        {
            if (a1.Length == a2.Length)
            {
                for (int i = 0; i < a1.Length; i++)
                {
                    if (a1[i] != a2[i])
                    {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }
    }
}
