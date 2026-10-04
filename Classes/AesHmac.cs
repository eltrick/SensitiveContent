using SensitiveContent.Interfaces;
using System.Numerics;
using System.Security.Cryptography;

namespace SensitiveContent.Classes
{
    internal class AesHmac : IAuthenticatedSymmetricCipher
    {
        private static readonly int _maxKeysInHistory = 32;
        private const string _keyCheckMagic = "verify_key_aes";
        private static readonly int[] _keyLengths = [32, 64];
        private static readonly int[] _iterationCounts = [1, 1];
        private readonly List<byte[][]> _keyHistory = [];
        private readonly Aes _aes;
        private readonly HMACSHA256 _hmac;

        public AesHmac()
        {
            _aes = Aes.Create();
            _hmac = new();

            SaveCurrentKeys();
        }

        public AesHmac(params byte[][] keys)
        {
            _aes = Aes.Create();
            _hmac = new();

            UpdateKeys(keys);
        }

        public void SaveCurrentKeys()
        {
            _keyHistory.Add([_aes.Key, _hmac.Key]);
            if (_keyHistory.Count > _maxKeysInHistory)
                _keyHistory.RemoveAt(0);
        }

        public List<byte[][]> GetKeyHistory()
        {
            return _keyHistory;
        }

        public int[] GetKeyLengths()
        {
            return _keyLengths;
        }

        public int[] GetIterationCounts()
        {
            return _iterationCounts;
        }

        private void UpdateKeysTemp(params byte[][] keys)
        {
            if (Enumerable.Range(0, _keyLengths.Length).Any(x => keys[x].Length != _keyLengths[x]))
                throw new CryptographicException($"Unexpected key lengths. [expected {string.Join(", ", _keyLengths.Select(x => x.ToString()))}, got {string.Join(", ", keys.Select(x => x.Length.ToString()))}]");

            _aes.Key = keys[0];
            _hmac.Key = keys[1];
        }

        public void UpdateKeys(params byte[][] keys)
        {
            UpdateKeysTemp(keys);
            SaveCurrentKeys();
        }

        private byte[] ComputeHash(string s)
        {
            return ComputeHash(FileHandler.FromString(s));
        }

        private byte[] ComputeHash(byte[] b)
        {
            return _hmac.ComputeHash(b);
        }

        public string KeyChecksum()
        {
            BigInteger r = BigInteger.Abs(new(ComputeHash(_keyCheckMagic)));

            List<string> parts = [];
            while (r != 0)
            {
                parts.Add((r % 1000000).ToString().PadLeft(6, '0'));
                r /= 1000000;
            }

            return string.Join(' ', parts);
        }

        public byte[] EncryptString((string, string) inputWithAAD)
        {
            return Encrypt((FileHandler.FromString(inputWithAAD.Item1), FileHandler.FromString(inputWithAAD.Item2)));
        }

        public (string, string) DecryptString(byte[] blob)
        {
            var ptAad = Decrypt(blob);

            return (FileHandler.ToString(ptAad.Item1), FileHandler.ToString(ptAad.Item2));
        }

        public byte[] Encrypt((byte[], byte[]) plaintextWithAAD)
        {
            _aes.GenerateIV();

            var (plaintext, aad) = plaintextWithAAD;

            byte[] ciphertext = _aes.EncryptCfb(plaintext, _aes.IV);
            byte[] mac = _hmac.ComputeHash(FileHandler.Concat(_aes.IV, aad, ciphertext));

            return FileHandler.SerializeCiphertext(_aes.IV, aad, ciphertext, mac);
        }

        public (byte[], byte[]) Decrypt(byte[] blob)
        {
            var (iv, aad, ciphertext, mac) = FileHandler.DeserializeCiphertext(blob);

            for (int i = 0; i < _keyHistory.Count; i++)
            {
                UpdateKeysTemp(_keyHistory[i]);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(_hmac.ComputeHash(FileHandler.Concat(iv, aad, ciphertext)), mac))
                        continue;

                    _keyHistory.RemoveAt(i);
                    return (_aes.DecryptCfb(ciphertext, iv), aad);
                }
                catch
                {
                    continue;
                }
            }

            return ([], []);
        }
    }
}
