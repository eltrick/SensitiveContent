using SensitiveContent.Interfaces;
using System.Security.Cryptography;

namespace SensitiveContent.Classes
{
    internal class DoubleRatchet(IAuthenticatedSymmetricCipher sendingCipher, IAuthenticatedSymmetricCipher receivingCipher)
    {
        private const byte _keyDerivationKeyId = 0;
        private const int _keyDerivationKeyLength = 32, _keyDerivationKeyIterations = 1;
        private byte _sendingNumber = 0, _receivingNumber = 0, _previousNumber = 0;
        private byte[] _keyDerivationKey = RandomNumberGenerator.GetBytes(_keyDerivationKeyLength);
        private byte[] _sendingChainKey = new byte[32];
        private byte[] _receivingChainKey = new byte[32];
        private readonly IAuthenticatedSymmetricCipher _sendingCipher = sendingCipher, _receivingCipher = receivingCipher;
        private Ecdh _currentRatchetPair = new();
        private Ecdh? _recipientRatchetPublic = null;

        public DoubleRatchet(IAuthenticatedSymmetricCipher sendingCipher, IAuthenticatedSymmetricCipher receivingCipher, byte[] keyDerivationKey) : this(sendingCipher, receivingCipher)
        {
            _keyDerivationKey = keyDerivationKey;
        }

        public DoubleRatchet(IAuthenticatedSymmetricCipher sendingCipher, IAuthenticatedSymmetricCipher receivingCipher, byte[] keyDerivationKey, Ecdh ratchetPair) : this(sendingCipher, receivingCipher, keyDerivationKey)
        {
            _currentRatchetPair = ratchetPair;
        }

        public byte[] GetKDK()
        {
            return _keyDerivationKey;
        }

        public byte[] EncryptString(string plaintext)
        {
            return Encrypt(FileHandler.FromString(plaintext));
        }

        public string DecryptString(byte[] blob)
        {
            return FileHandler.ToString(Decrypt(blob));
        }

        public byte[] Encrypt(byte[] input)
        {
            UpdateSendingKeys();

            return _sendingCipher.Encrypt((input, [.. _currentRatchetPair.ExportPublicKey().Concat([_previousNumber, _sendingNumber++])]));
        }

        public byte[] Decrypt(byte[] blob)
        {
            byte[] aad = FileHandler.DeserializeCiphertext(blob).Item2;
            byte pn = aad[^2];
            byte n = aad[^1];

            Ecdh possibleNewKey = new([.. aad.SkipLast(2)]);
            if (_recipientRatchetPublic != null && !_recipientRatchetPublic.IsEqual(possibleNewKey))
            {
                for (int i = 0; i < pn - _receivingNumber; i++)
                    UpdateReceivingKeys();

                DiffieHellmanRatchetStep(possibleNewKey);

                for (int i = 0; i < n; i++)
                    UpdateReceivingKeys();
            }
            else
            {
                if (_recipientRatchetPublic == null)
                    DiffieHellmanRatchetStep(possibleNewKey);

                for (int i = 0; i < n - _receivingNumber; i++)
                    UpdateReceivingKeys();
            }

            UpdateReceivingKeys();

            _receivingNumber = n;

            return _receivingCipher.Decrypt(blob).Item1;
        }

        public string PrintPublicKey()
        {
            return _currentRatchetPair.PrintPublicKey();
        }

        public Ecdh GenerateKey()
        {
            _currentRatchetPair = new();
            return _currentRatchetPair;
        }

        private void UpdateSendingKeys()
        {
            _sendingChainKey = Kdf.DeriveBytes(_sendingChainKey, [_keyDerivationKeyId], _keyDerivationKeyIterations, _keyDerivationKeyLength);
            _sendingCipher.UpdateKeys(Kdf.DeriveBytes(_sendingChainKey, _sendingCipher.GetIterationCounts(), _sendingCipher.GetKeyLengths()));
        }

        private void UpdateReceivingKeys()
        {
            _receivingChainKey = Kdf.DeriveBytes(_receivingChainKey, [_keyDerivationKeyId], _keyDerivationKeyIterations, _keyDerivationKeyLength);
            _receivingCipher.UpdateKeys(Kdf.DeriveBytes(_receivingChainKey, _receivingCipher.GetIterationCounts(), _receivingCipher.GetKeyLengths()));
        }

        private void UpdateKeyDerivationKey()
        {
            _keyDerivationKey = Kdf.DeriveBytes(_keyDerivationKey, [_keyDerivationKeyId], _keyDerivationKeyIterations, _keyDerivationKeyLength);
        }

        public void Init(Ecdh second)
        {
            _recipientRatchetPublic = second;
            _sendingChainKey = _currentRatchetPair.DeriveKey(_recipientRatchetPublic);
        }

        public void DiffieHellmanRatchetStep(Ecdh second)
        {
            _recipientRatchetPublic = second;
            _receivingChainKey = _currentRatchetPair.DeriveKey(_recipientRatchetPublic);
            _sendingChainKey = GenerateKey().DeriveKey(_recipientRatchetPublic);
        }
    }
}
