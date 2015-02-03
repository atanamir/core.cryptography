using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Cryptography.Internal
{
    internal class Binary
    {
        public static uint RotateLeft(uint x, int n)
        {
            return (x << n) | (x >> (32 - n));
        }

        public static ulong RotateLeft(ulong x, int n)
        {
            return (x << n) | (x >> (64 - n));
        }
    }
}
