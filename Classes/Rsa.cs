using System.Security.Cryptography;

namespace SensitiveContent.Classes
{
    internal class Rsa
    {
        private const int _keySizeBits = 2048;
        private const string _cipherType = "rsa";

        private RSA? _second;

        private readonly RSA _rsa;
        private readonly RSAEncryptionPadding _encryptionPadding = RSAEncryptionPadding.OaepSHA256;
        private readonly HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;
        private readonly RSASignaturePadding _signaturePadding = RSASignaturePadding.Pss;
        private readonly FileHandler _fileHandler = new();

        public Rsa()
        {
            _rsa = RSA.Create(_keySizeBits);
        }
        
        public Rsa(string data)
        {
            _rsa = RSA.Create();
            if (data.EndsWith($".{FileHandler.KeyExtension}"))
                _rsa.ImportRSAPrivateKey(_fileHandler.ReadKeyFile(data), out int _);
            else
                _rsa.ImportRSAPublicKey(FileHandler.FromBase64(data), out int _);
        }

        public void ExportPrivateKey()
        {
            _fileHandler.WriteKeyFile(_fileHandler.FormatFilename(_cipherType, "private", FileHandler.KeyExtension), _rsa.ExportRSAPrivateKey());
        }

        public string PrintPublicKey()
        {
            return FileHandler.ToBase64(_rsa.ExportRSAPublicKey());
        }

        public void ImportSecondPublicKey(string data)
        {
            _second = RSA.Create();
            _second.ImportRSAPublicKey(FileHandler.FromBase64(data), out int _);
        }

        public byte[] Encrypt(byte[] input)
        {
            if (_second == null)
                return [];

            byte[] mac = _rsa.SignData(input, _hashAlgorithm, _signaturePadding);
            byte[] ciphertext = _second.Encrypt([.. input.Concat(mac)], _encryptionPadding);

            return ciphertext;
        }

        public byte[] Decrypt(byte[] input)
        {
            if (_second == null)
                return [];

            try
            {
                byte[] combined = _rsa.Decrypt(input, _encryptionPadding);
                byte[] plaintext = combined.AsSpan(0, combined.Length - _keySizeBits / 8).ToArray();
                byte[] mac = combined.AsSpan(plaintext.Length).ToArray();

                if (!_second.VerifyData(plaintext, mac, _hashAlgorithm, _signaturePadding))
                    return [];

                return plaintext;
            }
            catch (Exception)
            {
                return [];
            }
        }
    }
}
