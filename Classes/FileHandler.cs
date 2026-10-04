using System.Text;

namespace SensitiveContent.Classes
{
#pragma warning disable CA1822
    internal class FileHandler
    {
        private const string _keyFolder = "keys";
        private const string _dateFormat = "yyyy-MM-dd";
        public readonly DirectoryInfo KeyDirectory = new(_keyFolder);
        public const string KeyExtension = "key";

        public FileHandler()
        {
            if (!KeyDirectory.Exists)
                KeyDirectory.Create();
        }

        public string FormatFilename(string prefix = "", string suffix = "", string ext = KeyExtension)
        {
            return $"{prefix}-{DateTime.Now.ToString(_dateFormat)}-{Guid.NewGuid()}-{suffix}.{ext}";
        }

        private string GetFullKeyPath(string filename)
        {
            return $"${KeyDirectory.FullName}\\{filename}";
        }

        public string ReadText(string filename)
        {
            return File.ReadAllText(filename);
        }

        public void WriteText(string filename, string content)
        {
            File.WriteAllText(filename, content);
        }

        public byte[] ReadRaw(string filename)
        {
            return File.ReadAllBytes(filename);
        }

        public void WriteRaw(string filename, byte[] content)
        {
            File.WriteAllBytes(filename, content);
        }

        public byte[] ReadKeyFile(string filename)
        {
            return File.ReadAllBytes(GetFullKeyPath(filename));
        }

        public void WriteKeyFile(string filename, byte[] content)
        {
            File.WriteAllBytes(GetFullKeyPath(filename), content);
        }

        public static byte[] EncodeLength(int length)
        {
            int c = length;
            byte[] r = [];
            bool flag = false;

            do
            {
                byte t = (byte)(c & 0x7f);
                t |= (byte)(flag ? 0x80 : 0x00);
                c >>= 7;
                flag = c > 0;

                r = [.. r.Prepend(t)];
            } while (c > 0);

            return r;
        }

        public static int DecodeLength(byte[] vleLength)
        {
            int r = 0;

            for (int i = 0; i < vleLength.Length; i++)
            {
                r <<= 7;
                r += vleLength[i] & 0x7F;
            }

            return r;
        }

        public static (int, byte[]) AsVLE(byte[] input, int start)
        {
            int c = start;
            byte[] r = [];

            do
                r = [.. r.Concat([input[c++]])];
            while (r[^1] > 0x7F);

            return (c, r);
        }

        public static byte[] Concat(params byte[][] arrays)
        {
            byte[] r = [];

            foreach (byte[] a in arrays)
                r = [.. r.Concat(a)];

            return r;
        }

        public static byte[] SerializeCiphertext(byte[] iv, byte[] aad, byte[] ciphertext, byte[] mac)
        {
            byte[] r = [];

            r = [.. r.Concat(EncodeLength(iv.Length)).Concat(iv)];
            r = [.. r.Concat(EncodeLength(aad.Length)).Concat(aad)];
            r = [.. r.Concat(EncodeLength(ciphertext.Length)).Concat(ciphertext)];
            r = [.. r.Concat(EncodeLength(mac.Length)).Concat(mac)];

            return r;
        }
        
        public static (byte[], byte[], byte[], byte[]) DeserializeCiphertext(byte[] stream)
        {
            int ptr = 0;
        
            // IV
            (int, byte[]) current = AsVLE(stream, ptr);

            ptr = current.Item1;
            int ivLength = DecodeLength(current.Item2);
            byte[] iv = [.. stream.AsSpan(ptr, ivLength)];
            ptr += ivLength;

            // AAD
            current = AsVLE(stream, ptr);

            ptr = current.Item1;
            int aadLength = DecodeLength(current.Item2);
            byte[] aad = [.. stream.AsSpan(ptr, aadLength)];
            ptr += aadLength;

            // CT
            current = AsVLE(stream, ptr);

            ptr = current.Item1;
            int ciphertextLength = DecodeLength(current.Item2);
            byte[] ciphertext = [.. stream.AsSpan(ptr, ciphertextLength)];
            ptr += ciphertextLength;

            // MAC
            current = AsVLE(stream, ptr);

            ptr = current.Item1;
            int macLength = DecodeLength(current.Item2);
            byte[] mac = [.. stream.AsSpan(ptr, macLength)];
            ptr += macLength;

            return (iv, aad, ciphertext, mac);
        }

        public static byte[] FromBase64(string input)
        {
            try
            {
                return Convert.FromBase64String(input);
            }
            catch (FormatException)
            {
                return [];
            }
        }

        public static string ToBase64(byte[] input)
        {
            return Convert.ToBase64String(input);
        }

        public static byte[] FromString(string input)
        {
            return Encoding.UTF8.GetBytes(input);
        }

        public static string ToString(byte[] input)
        {
            return Encoding.UTF8.GetString(input);
        }

        public static void ReadKey()
        {
            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
        }

        public static int GetInt(string label, int low = int.MinValue, int high = int.MaxValue)
        {
            int r;
            bool valid;
            do
            {
                Console.Write($"{label}: ");

                valid = int.TryParse(Console.ReadLine()!, out r);

                if (!valid || r < low || r > high)
                    Console.WriteLine("Invalid input");
            } while (!valid || r < low || r > high);

            return r;
        }
    }
#pragma warning restore CA1822
}
