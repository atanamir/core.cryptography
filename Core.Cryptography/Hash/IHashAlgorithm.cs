using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Cryptography.Hash
{
    public interface IHashAlgorithm
    {
        void Reset();

        void Update(byte[] data, int offset, int length);

        int Final(byte[] buffer, int offset);

        int DigestSize { get; }
    }

    public interface ISecureHashAlgorithm : IHashAlgorithm
    {
    }
}
