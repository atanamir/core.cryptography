namespace Core.Cryptography.Hash
{
    using System;
    using System.Security.AccessControl;

    using Internal;

    public class MD5 : HashAlgorithmBase
    {
        private uint _a, _b, _c, _d;

        public override int DigestSize
        {
            get { return 16; }
        }
        
        public override unsafe int Final(byte[] buffer, int offset)
        {
            if (offset + DigestSize < buffer.Length)
            {
                throw new ArgumentException();
            }

            BlockBuffer[CachedBytes++] = 0x80;

            if (CachedBytes == BlockSize)
            {
                TransformBlock(BlockBuffer, 0, BlockSize);
                CachedBytes = 0;
                Array.Clear(BlockBuffer, 0, BlockSize);
            }
            else if(CachedBytes + 8 > BlockSize)
            {
                Array.Clear(BlockBuffer, CachedBytes, BlockSize - CachedBytes);
                TransformBlock(BlockBuffer, 0, BlockSize);
                CachedBytes = 0;
            }

            if (BlockSize - CachedBytes > 8)
            {
                Array.Clear(BlockBuffer, CachedBytes, BlockSize - CachedBytes - 8);
            }

            fixed (byte* ptr = &BlockBuffer[56])
            {
                MessageLength = checked(MessageLength * 8);
                ulong* p = (ulong*)ptr;
                *p = MessageLength;
            }

            TransformBlock(BlockBuffer, 0, BlockSize);

            fixed (byte* b = &buffer[offset])
            {
                uint* ptr = (uint*)b;
                ptr[0] = _a;
                ptr[1] = _b;
                ptr[2] = _c;
                ptr[3] = _d;
            }

            return DigestSize;
        }

        public override void Reset()
        {
            _a = 0x67452301U;
            _b = 0xefcdab89U;
            _c = 0x98badcfeU;
            _d = 0x10325476U;

            base.Reset();
        }

        protected override unsafe void TransformBlock(byte[] buffer, int offset, int length)
        {
            var a = _a;
            var b = _b;
            var c = _c;
            var d = _d;

            fixed (byte* ptr = &buffer[offset])
            {
                var p = (uint*)ptr;

                StepF(ref a, b, c, d, p[0], 0xd76aa478U, 7);
                StepF(ref d, a, b, c, p[1], 0xe8c7b756U, 12);
                StepF(ref c, d, a, b, p[2], 0x242070dbU, 17);
                StepF(ref b, c, d, a, p[3], 0xc1bdceeeU, 22);
                StepF(ref a, b, c, d, p[4], 0xf57c0fafU, 7);
                StepF(ref d, a, b, c, p[5], 0x4787c62aU, 12);
                StepF(ref c, d, a, b, p[6], 0xa8304613U, 17);
                StepF(ref b, c, d, a, p[7], 0xfd469501U, 22);
                StepF(ref a, b, c, d, p[8], 0x698098d8U, 7);
                StepF(ref d, a, b, c, p[9], 0x8b44f7afU, 12);
                StepF(ref c, d, a, b, p[10], 0xffff5bb1U, 17);
                StepF(ref b, c, d, a, p[11], 0x895cd7beU, 22);
                StepF(ref a, b, c, d, p[12], 0x6b901122U, 7);
                StepF(ref d, a, b, c, p[13], 0xfd987193U, 12);
                StepF(ref c, d, a, b, p[14], 0xa679438eU, 17);
                StepF(ref b, c, d, a, p[15], 0x49b40821U, 22);

                /* Round 2 */
                StepG(ref a, b, c, d, p[1], 0xf61e2562U, 5);
                StepG(ref d, a, b, c, p[6], 0xc040b340U, 9);
                StepG(ref c, d, a, b, p[11], 0x265e5a51U, 14);
                StepG(ref b, c, d, a, p[0], 0xe9b6c7aaU, 20);
                StepG(ref a, b, c, d, p[5], 0xd62f105dU, 5);
                StepG(ref d, a, b, c, p[10], 0x02441453U, 9);
                StepG(ref c, d, a, b, p[15], 0xd8a1e681U, 14);
                StepG(ref b, c, d, a, p[4], 0xe7d3fbc8U, 20);
                StepG(ref a, b, c, d, p[9], 0x21e1cde6U, 5);
                StepG(ref d, a, b, c, p[14], 0xc33707d6U, 9);
                StepG(ref c, d, a, b, p[3], 0xf4d50d87U, 14);
                StepG(ref b, c, d, a, p[8], 0x455a14edU, 20);
                StepG(ref a, b, c, d, p[13], 0xa9e3e905U, 5);
                StepG(ref d, a, b, c, p[2], 0xfcefa3f8U, 9);
                StepG(ref c, d, a, b, p[7], 0x676f02d9U, 14);
                StepG(ref b, c, d, a, p[12], 0x8d2a4c8aU, 20);

                /* Round 3 */
                StepH(ref a, b, c, d, p[5], 0xfffa3942U, 4);
                StepH(ref d, a, b, c, p[8], 0x8771f681U, 11);
                StepH(ref c, d, a, b, p[11], 0x6d9d6122U, 16);
                StepH(ref b, c, d, a, p[14], 0xfde5380cU, 23);
                StepH(ref a, b, c, d, p[1], 0xa4beea44U, 4);
                StepH(ref d, a, b, c, p[4], 0x4bdecfa9U, 11);
                StepH(ref c, d, a, b, p[7], 0xf6bb4b60U, 16);
                StepH(ref b, c, d, a, p[10], 0xbebfbc70U, 23);
                StepH(ref a, b, c, d, p[13], 0x289b7ec6U, 4);
                StepH(ref d, a, b, c, p[0], 0xeaa127faU, 11);
                StepH(ref c, d, a, b, p[3], 0xd4ef3085U, 16);
                StepH(ref b, c, d, a, p[6], 0x04881d05U, 23);
                StepH(ref a, b, c, d, p[9], 0xd9d4d039U, 4);
                StepH(ref d, a, b, c, p[12], 0xe6db99e5U, 11);
                StepH(ref c, d, a, b, p[15], 0x1fa27cf8U, 16);
                StepH(ref b, c, d, a, p[2], 0xc4ac5665U, 23);

                /* Round 4 */
                StepI(ref a, b, c, d, p[0], 0xf4292244U, 6);
                StepI(ref d, a, b, c, p[7], 0x432aff97U, 10);
                StepI(ref c, d, a, b, p[14], 0xab9423a7U, 15);
                StepI(ref b, c, d, a, p[5], 0xfc93a039U, 21);
                StepI(ref a, b, c, d, p[12], 0x655b59c3U, 6);
                StepI(ref d, a, b, c, p[3], 0x8f0ccc92U, 10);
                StepI(ref c, d, a, b, p[10], 0xffeff47dU, 15);
                StepI(ref b, c, d, a, p[1], 0x85845dd1U, 21);
                StepI(ref a, b, c, d, p[8], 0x6fa87e4fU, 6);
                StepI(ref d, a, b, c, p[15], 0xfe2ce6e0U, 10);
                StepI(ref c, d, a, b, p[6], 0xa3014314U, 15);
                StepI(ref b, c, d, a, p[13], 0x4e0811a1U, 21);
                StepI(ref a, b, c, d, p[4], 0xf7537e82U, 6);
                StepI(ref d, a, b, c, p[11], 0xbd3af235U, 10);
                StepI(ref c, d, a, b, p[2], 0x2ad7d2bbU, 15);
                StepI(ref b, c, d, a, p[9], 0xeb86d391U, 21);
            }

            _a += a;
            _b += b;
            _c += c;
            _d += d;
        }

        private static uint F(uint x, uint y, uint z)
        {
            return z ^ (x & (y ^ z));
        }

        private static uint G(uint x, uint y, uint z)
        {
            return x & z | y & ~z;
        }

        private static uint H(uint x, uint y, uint z)
        {
            return x ^ y ^ z;
        }

        private static uint I(uint x, uint y, uint z)
        {
            return y ^ (x | ~z);
        }

        private static void Boo(ref uint a, uint val, uint b, uint x, uint t, int s)
        {
            a = Binary.RotateLeft(a + val + x + t, s) + b;
        }

        private static void StepF(ref uint a, uint b, uint c, uint d, uint x, uint t, int s)
        {
            var val = F(b, c, d); //  (d ^ (b & (c ^ d))); // b & c | ~b & d;
            Boo(ref a, val, b, x, t, s);
        }

        private static void StepG(ref uint a, uint b, uint c, uint d, uint x, uint t, int s)
        {
            var val = G(b, c, d);
            Boo(ref a, val, b, x, t, s);
        }

        private static void StepH(ref uint a, uint b, uint c, uint d, uint x, uint t, int s)
        {
            var val = H(b, c, d);
            Boo(ref a, val, b, x, t, s);
        }

        private static void StepI(ref uint a, uint b, uint c, uint d, uint x, uint t, int s)
        {
            var val = I(b, c, d);
            Boo(ref a, val, b, x, t, s);
        }

        protected override int BlockSize
        {
            get { return 64; }
        }
    }
}
