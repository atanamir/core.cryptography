using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Cryptography.Hash
{
    using System.Security.Cryptography;

    public abstract class HashAlgorithmBase : IHashAlgorithm
    {
        protected byte[] BlockBuffer;
        protected int CachedBytes;
        protected ulong MessageLength;

        public abstract int DigestSize { get; }

        protected abstract int BlockSize { get; }

        protected HashAlgorithmBase()
        {
            Reset();
        }
        
        public void Update(byte[] data, int offset, int length)
        {
            if (data == null)
            {
                throw new ArgumentNullException();
            }

            if (length < 0)
            {
                throw new ArgumentException("Length must be non-negative.");
            }
            if (length > data.Length - offset)
            {
                throw new ArgumentException("Length is ");
            }

            MessageLength += (uint)length;

            if (CachedBytes > 0)
            {
                int n = Math.Min(length, BlockSize - CachedBytes);
                Buffer.BlockCopy(data, offset, BlockBuffer, CachedBytes, n);
                CachedBytes += n;
                offset += n;
                length -= n;

                if (CachedBytes == BlockSize)
                {
                    TransformBlock(BlockBuffer, 0, BlockSize);
                    CachedBytes = 0;
                }
            }

            while (length >= BlockSize)
            {
                TransformBlock(data, offset, length);
                offset += BlockSize;
                length -= BlockSize;
            }
            
            while (length > 0)
            {
                int n = Math.Min(length, BlockSize - CachedBytes);
                Buffer.BlockCopy(data, offset, BlockBuffer, CachedBytes, n);
                CachedBytes += n;
                offset += n;
                length -= n;

                if (CachedBytes == BlockSize)
                {
                    TransformBlock(BlockBuffer, 0, BlockSize);
                    CachedBytes = 0;
                }
            }
        }

        public abstract int Final(byte[] buffer, int offset);

        public virtual void Reset()
        {
            BlockBuffer = new byte[BlockSize];
            MessageLength = 0;
        }

        protected abstract void TransformBlock(byte[] buffer, int offset, int length);
    }
}
