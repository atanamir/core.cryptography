using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Cryptography.Hash
{
    using System.Linq.Expressions;

    using Core.Cryptography.Internal;

    public interface IMurmurHash3 : IHashAlgorithm { }

    internal class MurmurHash3
    {
        public static IMurmurHash3 Create128(ulong seed)
        {
            return new Hash128(seed);
        }

        private class Hash128 : HashAlgorithmBase, IMurmurHash3
        {
            private const ulong Constant1 = 0x87c37b91114253d5;
            private const ulong Constant2 = 0x4cf5ad432745937f;

            private ulong _h1, _h2;
            private readonly ulong _seed;

            public Hash128(ulong seed)
            {
                _seed = seed;
            }

            public override int DigestSize
            {
                get { return 128 / 8; }
            }

            protected override int BlockSize
            {
                get { return 16; }
            }

            public override void Reset()
            {
                base.Reset();
                _h1 = _seed;
                _h2 = _seed;
            }

            public override unsafe int Final(byte[] buffer, int offset)
            {
                if (CachedBytes > 0)
                {
                    ulong k1 = 0, k2 = 0;

                    while (CachedBytes > 8)
                    {
                        
                    }

                    while (CachedBytes > 0)
                    {
                        
                    }
                }

                _h1 ^= MessageLength;
                _h2 ^= MessageLength;

                _h1 += _h2;
                _h2 += _h1;

                _h1 = Mix(_h1);
                _h2 = Mix(_h2);

                _h1 += _h2;
                _h2 += _h1;

                fixed (byte* b = &buffer[offset])
                {
                    ulong* ptr = (ulong*)b;
                    ptr[0] = _h1;
                    ptr[1] = _h2;
                }
                return DigestSize;
            }

            private static ulong Mix(ulong k)
            {
                k ^= k >> 33;
                k *= 0xff51afd7ed558ccdUL;
                k ^= k >> 33;
                k *= 0xc4ceb9fe1a85ec53UL;
                k ^= k >> 33;
                return k;
            }

            protected override unsafe void TransformBlock(byte[] buffer, int offset, int length)
            {
                fixed (byte* b = &buffer[offset])
                {
                    ulong* ptr = (ulong*)b;
                    var k1 = ptr[0];
                    var k2 = ptr[1];

                    k1 *= Constant1;
                    k1 = Binary.RotateLeft(k1, 31);
                    k1 *= Constant2;
                    _h1 ^= k1;
                    _h1 = Binary.RotateLeft(_h1, 27);
                    _h1 += _h2;
                    _h1 = _h1 * 5 + 0x52dce729;

                    k2 *= Constant2;
                    k2 = Binary.RotateLeft(k2, 33);
                    k2 *= Constant1;
                    _h2 ^= k2;
                    _h2 = Binary.RotateLeft(_h2, 31);
                    _h2 += _h1;
                    _h2 = _h2 * 5 + 0x38495ab5;
                }
            }
        }
    }
}