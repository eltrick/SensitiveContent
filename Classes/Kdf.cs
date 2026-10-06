using System.Security.Cryptography;

namespace SensitiveContent.Classes
{
    internal class Kdf
    {
        private static readonly HashAlgorithmName _alg = HashAlgorithmName.SHA256;

        public static byte[] DeriveBytes(byte[] currentKey, Ecdh sk, Ecdh opk, int length)
        {
            return DeriveBytes(currentKey, length, sk.DeriveKey(opk));
        }

        public static byte[] DeriveBytes(byte[] password, int length, byte[]? salt = null)
        {
            return HKDF.DeriveKey(_alg, password, length, salt);
        }

        public static byte[][] DeriveBytes(byte[] password, int[] keyLengths, byte[]? salt = null)
        {
            byte[][] r = new byte[keyLengths.Length][];

            for (int i = 0; i < keyLengths.Length; i++)
                r[i] = DeriveBytes(password, keyLengths[i], salt == null ? [(byte)(i + 1)] : [.. salt.Concat([(byte)(i + 1)])]);

            return r;
        }
    }
}
