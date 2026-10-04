using System.Security.Cryptography;

namespace SensitiveContent.Classes
{
    internal class Ecdh
    {
        private const string _keyType = "ecdh";

        private readonly ECDiffieHellman _ecdh;
        private readonly FileHandler _fileHandler = new();

        public Ecdh()
        {
            _ecdh = ECDiffieHellman.Create();
        }

        public Ecdh(byte[] data)
        {
            _ecdh = ECDiffieHellman.Create();
            _ecdh.ImportSubjectPublicKeyInfo(data, out int _);
        }

        public Ecdh(string data)
        {
            _ecdh = ECDiffieHellman.Create();
            if (data.EndsWith($".{FileHandler.KeyExtension}"))
                _ecdh.ImportECPrivateKey(_fileHandler.ReadKeyFile(data), out int _);
            else
                _ecdh.ImportSubjectPublicKeyInfo(Convert.FromBase64String(data), out int _);
        }

        public ECDiffieHellmanPublicKey GetPublicKey()
        {
            return _ecdh.PublicKey;
        }

        public void ExportPrivateKey()
        {
            _fileHandler.WriteKeyFile(_fileHandler.FormatFilename(_keyType, "private", FileHandler.KeyExtension), _ecdh.ExportECPrivateKey());
        }

        public byte[] ExportPublicKey()
        {
            return _ecdh.ExportSubjectPublicKeyInfo();
        }

        public string PrintPublicKey()
        {
            return FileHandler.ToBase64(_ecdh.ExportSubjectPublicKeyInfo());
        }

        public byte[] DeriveKey(Ecdh second)
        {
            return _ecdh.DeriveKeyMaterial(second.GetPublicKey());
        }

        public bool IsEqual(Ecdh second)
        {
            return PrintPublicKey() == second.PrintPublicKey();
        }
    }
}
