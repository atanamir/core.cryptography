using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Cryptography.Hash
{
    using System.IO;
    using System.Threading;

    public static class HashAlgorithmExtensions
    {
        public static byte[] Final(this IHashAlgorithm algorithm)
        {
            var digest = new byte[algorithm.DigestSize];
            int length = algorithm.Final(digest, 0);
            if (length != digest.Length)
            {
                throw new Exception();
            }
            return digest;
        }

        public static byte[] ComputeHash(this IHashAlgorithm algorithm, Stream s)
        {
            return null;
        }

        public static Task<byte[]> ComputeHashAsync(this IHashAlgorithm algorithm, Stream s, CancellationToken token)
        {
            return null;
        }

        public static byte[] ComputeHash(this IHashAlgorithm algorithm, byte[] data)
        {
            return ComputeHash(algorithm, data, 0, data.Length);
        }

        public static byte[] ComputeHash(this IHashAlgorithm algorithm, byte[] data, int offset, int length)
        {
            algorithm.Reset();
            algorithm.Update(data, offset, length);
            return algorithm.Final();  
        }
    }
}
