namespace SensitiveContent.Interfaces
{
    internal interface IAuthenticatedSymmetricCipher
    {
        public void UpdateKeys(params byte[][] keys);

        /// <summary>
        /// Encrypt an input blob.
        /// </summary>
        /// <param name="input">The input [a tuple containing the plaintext then additional authenticated data] to be encrypted-then-MACed</param>
        /// <returns>A byte array containing the IV, authenticated plaintext [if any], ciphertext, and MAC</returns>
        public byte[] Encrypt((byte[], byte[]) input);

        /// <summary>
        /// Try to decrypt an input blob, or return empty arrays if it fails
        /// </summary>
        /// <param name="input">The input blob to be checked and decrypted</param>
        /// <returns>A tuple containing the plaintext and additional authenticated data if decryption was successful, otherwise empty arrays</returns>
        public (byte[], byte[]) Decrypt(byte[] input);

        /// <summary>
        /// Encrypt a pair of strings.
        /// </summary>
        /// <param name="plainWithAad">A tuple of two strings [the first being plaintext, the second being additional authenticated data]</param>
        /// <returns>A byte array representing the encrypted blob.</returns>
        public byte[] EncryptString((string, string) plainWithAad);

        /// <summary>
        /// Try to decrypt a blob to a pair of strings.
        /// </summary>
        /// <param name="blob">A byte array containing the encrypted blob.</param>
        /// <returns>A tuple of strings [containing empty strings if it fails].</returns>
        public (string, string) DecryptString(byte[] blob);

        /// <summary>
        /// Gets the lengths of all required keys the cipher uses.
        /// </summary>
        /// <returns>An array of key lengths, in bytes, for each key the cipher uses.</returns>
        public int[] GetKeyLengths();

        public string KeyChecksum();
    }
}
