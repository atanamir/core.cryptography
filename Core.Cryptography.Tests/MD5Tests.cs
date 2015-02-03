using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Core.Cryptography.Hash;

namespace Core.Cryptography.Tests
{
    using System.Linq;
    using System.Text;

    [TestClass]
    public class MD5Tests
    {
        [TestMethod]
        public void Empty()
        {
            var md5 = new MD5();
            var hash = md5.ComputeHash(new byte[0]);

            if (!hash.SequenceEqual(ToBytes("d41d8cd98f00b204e9800998ecf8427e")))
            {
                throw new Exception();
            }
        }

        [TestMethod]
        public void Simple1()
        {
            var input = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");
            var md5 = new MD5();
            var hash = md5.ComputeHash(input);

            if (!hash.SequenceEqual(ToBytes("9e107d9d372bb6826bd81d3542a419d6")))
            {
                throw new Exception();
            }
        }

        [TestMethod]
        public void Simple2()
        {
            var input = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog.");
            var md5 = new MD5();
            var hash = md5.ComputeHash(input);

            if (!hash.SequenceEqual(ToBytes("e4d909c290d0fb1ca068ffaddf22cbd0")))
            {
                throw new Exception();
            }
        }

        [TestMethod]
        public void LongerThanOneBlock1()
        {
            var input = new byte[65];
            for (var i = 0; i < input.Length; i++)
            {
                input[i] = checked((byte)i);
            }

            var md5 = new MD5();
            var hash = md5.ComputeHash(input);
            
            if (!hash.SequenceEqual(ToBytes("8BD7053801C768420FAF816FADBA971C")))
            {
                throw new Exception();
            }
        }

        [TestMethod]
        public void SixtyThreeBytes()
        {
            var input = new byte[63];
            for (var i = 0; i < input.Length; i++)
            {
                input[i] = checked((byte)i);
            }

            var md5 = new MD5();
            var hash = md5.ComputeHash(input);

            if (!hash.SequenceEqual(ToBytes("48A6295221902E8E0938F773A7185E72")))
            {
                throw new Exception();
            }
        }

        [TestMethod]
        public void SixtyBytes()
        {
            var input = new byte[60];
            for (var i = 0; i < input.Length; i++)
            {
                input[i] = checked((byte)i);
            }

            var md5 = new MD5();
            var hash = md5.ComputeHash(input);

            if (!hash.SequenceEqual(ToBytes("63ED72093AE09E2C8553EE069E63D702")))
            {
                throw new Exception();
            }
        }

        [TestMethod]
        public void LongerThanOneBlock2()
        {
            var input = new byte[64 * 2 + 1];
            for (var i = 0; i < input.Length; i++)
            {
                input[i] = checked((byte)i);
            }

            var md5 = new MD5();
            var hash = md5.ComputeHash(input);

            if (!hash.SequenceEqual(ToBytes("46F986692847558FC38B0CECE591C20F")))
            {
                throw new Exception();
            }
        }

        private static byte[] ToBytes(string hex)
        {
            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException();
            }

            var result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                byte b;
                var first = hex[i * 2] - '0';
                var second = hex[i * 2 + 1] - '0';
                if (first >= 0 && first <= 9)
                {
                    // nothing
                }
                else if (first >= 49 && first <= 54)
                {
                    first -= 49;
                    first += 0xA;
                }
                else if(first >= 17 && first <= 22)
                {
                    first -= 17;
                    first += 0xA;
                }
                else
                {
                    throw new FormatException();
                }
                b = (byte)(first << 4);

                if (second >= 0 && second <= 9)
                {
                    // nothing
                }
                else if (second >= 49 && second <= 54)
                {
                    second -= 49;
                    second += 0xA;
                }
                else if (second >= 17 && second <= 22)
                {
                    second -= 17;
                    second += 0xA;
                }
                else
                {
                    throw new FormatException();
                }
                b |= (byte)second;
                result[i] = b;
            }
            return result;
        }
    }
}
