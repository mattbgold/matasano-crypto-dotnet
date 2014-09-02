using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto
{
    class BytesComparer : IEqualityComparer<IEnumerable<byte>>
    {

        public bool Equals(IEnumerable<byte> x, IEnumerable<byte> y)
        {
            return x.SequenceEqual(y);
        }

        public int GetHashCode(IEnumerable<byte> obj)
        {
            return obj.Count();
        }
    }
}
