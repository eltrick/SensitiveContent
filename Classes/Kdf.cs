using System.Security.Cryptography;

namespace SensitiveContent.Classes
{
    internal class Kdf
    {
        private static readonly HashAlgorithmName _alg = HashAlgorithmName.SHA256;

        public static byte[] DeriveBytes(byte[] currentKey, Ecdh sk, Ecdh opk, int iterations, int length)
        {
            return Rfc2898DeriveBytes.Pbkdf2(currentKey, sk.DeriveKey(opk), iterations, _alg, length);
        }

        public static byte[] DeriveBytes(byte[] password, byte[] salt, int iterations, int length)
        {
            return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, _alg, length);
        }

        public static byte[][] DeriveBytes(byte[] password, byte[] salt, int[] iterations, int[] keyLengths)
        {
            byte[][] r = new byte[keyLengths.Length][];

            for (int i = 0; i < keyLengths.Length; i++)
                r[i] = DeriveBytes(password, [..salt.Concat([(byte)(i + 1)])], iterations[i], keyLengths[i]);

            return r;
        }

        public static byte[][] DeriveBytes(byte[] password, int[] iterations, int[] keyLengths)
        {
            byte[][] r = new byte[keyLengths.Length][];
            
            for (int i = 0; i < keyLengths.Length; i++)
                r[i] = DeriveBytes(password, [(byte)(i + 1)], iterations[i], keyLengths[i]);

            return r;
        }
    }
}
